--[[

        server.lua by blastbeat

        - this script contains the server loop of the program
        - other scripts can reg a server here

            v0.09: by blastbeat
                - fixed client keeping alive issue

            v0.08: by pulsar
                - improved out_put/out_error messages

            v0.07: by blastbeat
                - added "handler.getsslinfo()" function

            v0.06: by pulsar
                - fix occasional unwanted disconnects in big hubs

            v0.05: by pulsar
                - increase timeout to prevent disconnects

            v0.04: by blastbeat
                - small fix

            v0.03: by blastbeat
                - try to manage SSL nightmare to fix Kungens disconnect bug

            v0.02: by pulsar
                - small fix


]]--

----------------------------------// DECLARATION //--

local clean = use "cleantable"

--// constants //--

local STAT_UNIT = 1    -- byte

--// lua functions //--

local type = use "type"
local pairs = use "pairs"
local ipairs = use "ipairs"
local tostring = use "tostring"
local tonumber = use "tonumber"

--// lua libs //--

local io = use "io"
local os = use "os"
local table = use "table"
local string = use "string"
local coroutine = use "coroutine"

--// lua lib methods //--

local io_open = io.open
local os_time = os.time
local os_difftime = os.difftime
local table_concat = table.concat
local string_len = string.len
local string_sub = string.sub
local coroutine_wrap = coroutine.wrap
local coroutine_yield = coroutine.yield

--// extern libs //--

local luasec = use "ssl"
local luasocket = use "socket"

--// extern lib methods //--

local ssl_wrap = ( luasec and luasec.wrap )
local socket_sleep = luasocket.sleep
local socket_select = luasocket.select
local ssl_newcontext = ( luasec and luasec.newcontext )

--// core scripts //--

local cfg = use "cfg"
local out = use "out"
local util = use "util"
local mem = use "mem"
local ratelimit = use "ratelimit"
local blocklist = use "blocklist"
local iostream = use "iostream"

--// core methods //--

local cfg_get = cfg.get
local out_put = out.put
local mem_free = mem.free
local out_error = out.error
local ratelimit_accept_ip = ratelimit.accept_ip
-- Platform gate for SO_REUSEADDR (see addserver): Linux needs it for the
-- TIME_WAIT fast-restart (#128); on Windows SO_REUSEADDR instead lets a
-- SECOND process re-bind a port already in use (SO_REUSEPORT-like
-- semantics), so a same-port second hub binds silently and any process
-- could hijack a luadch port. Skipping it on Windows makes that second
-- bind fail with WSAEADDRINUSE ("address already in use") so the operator
-- gets a clear message instead of two hubs racing.
local _is_windows = ( util.path_sep( ) == "\\" )
local ratelimit_release_ip = ratelimit.release_ip
local blocklist_check_ip = blocklist.check_ip
local ratelimit_handshake_started = ratelimit.handshake_started
local ratelimit_handshake_finished = ratelimit.handshake_finished
local ratelimit_expired_handshakes = ratelimit.expired_handshakes
local iostream_newpipeline = iostream.newpipeline
local iostream_newoutpipeline = iostream.newoutpipeline
local ratelimit_tick = ratelimit.tick

--// functions //--

local tick

local killall
local addtimer
local addserver
local wrapserver
local closesocket
local removesocket
local wrapconnection

local return_false
local do_nothing

--// tables //--

local _server
local _readlist
local _timerlist
local _sendlist
local _socketlist
local _closelist
local _activitytimes
local _writetimes

--// simple data types //--

local _
local _readlistlen
local _sendlistlen
local _timerlistlen

local _selecttimeout
local _sleeptime

local _starttime
local _currenttime

local _maxsendlen
local _maxreadlen

local _checkinterval
local _sendtimeout
local _max_idle_time
local _hs_sweep_last               -- #207: last-fire timestamp for the sweep

local _cleanqueue

local _timer

local _maxclientsperserver

----------------------------------// DEFINITION //--

_server = { }    -- key = port .. "/" .. family (e.g. "5001/ipv4"), value = table; list of listening servers
_readlist = { }    -- array with sockets to read from
_sendlist = { }    -- arrary with sockets to write to
_timerlist = { }    -- array of timer functions
_socketlist = { }    -- key = socket, value = wrapped socket (handlers)
_activitytimes = { }   -- key = handler, value = timestamp of last activity
_writetimes = { }   -- key = handler, value = timestamp of last data writing/sending
_closelist = { }    -- handlers to close

_readlistlen = 0    -- length of readlist
_sendlistlen = 0    -- length of sendlist
_timerlistlen = 0    -- lenght of timerlist

_selecttimeout = 1    -- timeout of socket.select
_sleeptime = 0.01    -- time to wait at the end of every tick

_maxsendlen = 1024 * 1024    -- max len of send buffer
_maxreadlen = 1024 * 1024    -- max len of read buffer

_checkinterval = 120    -- interval in secs to check clients for acitivty and
_sendtimeout = 60   -- allowed send idle time in secs
_max_idle_time = 30 * 60    -- allowed time of no read/write client activity in secs

_cleanqueue = false    -- clean bufferqueue after using

_maxclientsperserver = 10000

-- Closes #107: _server registry is keyed by (port, family) so the
-- same port number can serve both IPv4 and IPv6 (HTTP/80-style
-- dual-stack). The OS-level socket layer has always allowed
-- 0.0.0.0:N and [::]:N as independent sockets; what blocked us was
-- this Lua-side existence check. The bundled luasocket forces
-- IPV6_V6ONLY = 1 on every AF_INET6 socket at creation time
-- (luasocket/src/inet.c inet_trycreate), so the v6 listener does
-- NOT also accept v4-mapped traffic - a future luasocket fork that
-- drops that default would silently re-introduce the dual-stack-leak
-- bug; mind the comment in addserver() near the tcp6() branch.
local _serverkey = function( port, family )
    return tostring( port ) .. "/" .. ( family or "ipv4" )
end

----------------------------------// PRIVATE //--

wrapserver = function( listeners, socket, serverip, serverport, serverfamily, pattern, sslctx, maxconnections, startssl )    -- this function wraps a server

    local id = { }    -- connection id

    maxconnections = maxconnections or _maxclientsperserver

    local connections = 0

    local dispatch = listeners.incoming or listeners.listener

    local err

    local ssl = false

    if sslctx then
        if not ssl_newcontext then
            return nil, "luasec not found"
        elseif not cfg_get "use_ssl" then
            return nil, "ssl is deactivated"
        end
        if type( sslctx ) ~= "table" then
            out_error "server.lua: function 'wrapserver': wrong server sslctx"
            return nil, "wrong server sslctx"
        end
        -- Closes upstream luadch/luadch#177: the upstream error
        -- "wrong sslctx parameters: error loading private key (null)"
        -- is what LuaSec / OpenSSL emit when the configured key /
        -- certificate file is missing or unreadable. Detect that
        -- specific case here and surface a friendly hint instead.
        for _, field in ipairs( { "key", "certificate", "cafile" } ) do
            local path = sslctx[ field ]
            if path then
                local f = io_open( path, "r" )
                if f then
                    f:close( )
                else
                    local hint =
                        "TLS cert file '" .. tostring( path ) ..
                        "' (sslctx." .. field ..
                        ") is missing or unreadable. " ..
                        "Run certs/make_cert.{sh,bat} to generate a " ..
                        "self-signed cert, or set use_ssl = false in " ..
                        "cfg/cfg.tbl if you do not want TLS."
                    out_error( "server.lua: function 'wrapserver': ", hint )
                    return nil, hint
                end
            end
        end
        sslctx, err = ssl_newcontext( sslctx )
        if not sslctx then
            err = err or "wrong sslctx parameters"
            out_error( "server.lua: function 'wrapserver': wrong sslctx parameters: ", err )
            return nil, err
        end
        ssl = true
    else
        out_put( "server.lua: function 'wrapserver': ssl not enabled on ", serverport )
    end

    local accept = socket.accept

    --// public methods of the object //--

    local handler = { }

    handler.shutdown = function( )
        for _, h in pairs( _socketlist ) do
            if h.serverport( ) == serverport then
                h.close( )
            end
        end
        handler.readbuffer = return_false    -- dont accept anymore
    end

    handler.ssl = function( )
        return ssl
    end
    handler.remove = function( )
        connections = connections - 1
    end
    handler.close = function( )
        _closelist[ handler ] = "closed"
    end
    handler.kill = function( )
        out_put "server.lua: function 'wrapserver': try to close server handler, closing connected clients..."
        handler.readbuffer = return_false    -- dont read anymore
        _readlistlen = removesocket( _readlist, socket, _readlistlen )
        _sendlistlen = removesocket( _sendlist, socket, _sendlistlen )
        _socketlist[ socket ] = nil
        _writetimes[ handler ] = nil
        _activitytimes[ handler ] = nil
        _closelist[ handler ] = nil
        _server[ _serverkey( serverport, serverfamily ) ] = nil
        socket:close( )
        handler = nil
        socket = nil
        mem_free( )
        out_put "server.lua: function 'wrapserver': closed server handler and removed socket from lists"
    end
    handler.ip = function( )
        return serverip
    end
    handler.serverip = handler.ip
    handler.serverport = function( )
        return serverport
    end
    handler.readbuffer = function( )
        if connections > maxconnections then
            out_put( "server.lua: function 'wrapserver': refused new client connection: server full" )
            return false
        end
        local client, err = accept( socket )    -- try to accept
        if client then
            local clientip, clientport = client:getpeername( )
            -- A peer that reset the connection between accept() and here
            -- leaves getpeername() returning nil (remote-triggerable).
            -- We cannot blocklist / rate-limit an unknown IP and the
            -- socket is already dead; drop it before the accept guards
            -- rather than passing nil into them - feeding nil into
            -- ratelimit_accept_ip raised inside the accept loop and took
            -- the whole listener down (no new connections could be
            -- accepted; Sopor, 3.1.11).
            if not clientip then
                out_put( "server.lua: function 'wrapserver': accepted socket with no peer address (reset before getpeername), closing" )
                client:close( )
                return false
            end
            -- #78 Phase A: pre-handshake blocklist check. Runs BEFORE
            -- ratelimit_accept_ip so a blocked-IP flood does not drain
            -- the per-IP ratelimit budget for other (legitimate) IPs.
            -- core/blocklist.lua handles the aggregated-log rollup +
            -- per-attempt visible log; we just close-on-accept here
            -- to keep the rejection silent at the ADC layer (no
            -- ISTA reply because we have not started the handshake).
            local bl_blocked = blocklist_check_ip( clientip )
            if bl_blocked then
                client:close( )
                return false
            end
            -- Phase 7c F-NET-1: per-IP parallel-socket cap and per-IP
            -- accept-rate cap. Refuse pre-wrap so the offending IP cannot
            -- consume FDs / slot-list entries.
            local ok, rl_err = ratelimit_accept_ip( clientip )
            if not ok then
                out_put( "server.lua: function 'wrapserver': rate-limit refused ", clientip, ": ", rl_err )
                client:close( )
                return false
            end
            client:settimeout( 0 )
            local _, err = client:setoption( "reuseaddr", true )
            local _, err2 = client:setoption( "keepalive", true )
            if err or err2 then
                out_put( "server.lua: function 'wrapserver', luasocket socket setoption: ", err or err2 )
                ratelimit_release_ip( clientip )
                return false
            end
            local handler, client, err = wrapconnection( handler, listeners, client, serverip, clientip, serverport, clientport, pattern, sslctx, startssl )    -- wrap new client socket
            if err then    -- error while wrapping ssl socket
                ratelimit_release_ip( clientip )
                return false
            end
            connections = connections + 1
            out_put( "server.lua: function 'wrapserver': accepted new client connection from ", clientip, ":", clientport, " to ", serverport )
            return dispatch( handler )
        elseif err then    -- maybe timeout or something else
            out_put( "server.lua: function 'wrapserver': error with new client connection: ", err )
            return false
        end
    end
    return handler
end

wrapconnection = function( server, listeners, socket, serverip, clientip, serverport, clientport, pattern, sslctx, startssl, id )    -- this function wraps a client to a handler object

    id = id or { }

    socket:settimeout( 0 )

    --// local import of socket methods //--

    local send
    local receive

    --// private closures of the object //--

    local ssl

    local dispatch = listeners.incoming or listeners.listener
    local disconnect = listeners.disconnect

    local bufferqueue = { }    -- buffer array
    local bufferqueuelen = 0    -- end of buffer array

    -- Phase 8 S1/S2/S3/S4a: inbound + outbound transform pipelines.
    -- Replace LuaSocket's internal "*l" line buffer (inbound) and add
    -- a per-connection write-time transform seam (outbound). One pair
    -- per connection.
    --
    -- Inbound default = a single ADC-line stage; ADC listeners get
    -- that. HTTP listener supplies its own factory via
    -- listeners.pipeline (the hardened HTTP framer for #82). S4a
    -- changed the contract to lazy / iterator-style: server.lua does
    -- feed() + while next() loop instead of "give me all frames",
    -- because S4b will prepend an inflate stage mid-chunk on ZON and
    -- the loop MUST stop feeding the framer after the ZON frame so
    -- the post-ZON compressed suffix is not mis-parsed as ADC frames.
    --
    -- Outbound default = a single passthrough = identity transform,
    -- byte-for-byte equivalent to pre-S4a write behaviour. A listener
    -- may supply listeners.pipeline_out for a custom factory; S4b
    -- prepends a deflate_stream stage on outbound ZON.
    local inframer = ( listeners.pipeline or iostream_newpipeline )( _maxreadlen )
    local outframer = ( listeners.pipeline_out or iostream_newoutpipeline )( )

    local toclose
    local fatalerror

    local bufferlen = 0

    local noread = false
    local nosend = false

    local sendtraffic, readtraffic = 0, 0

    local maxsendlen = _maxsendlen
    local maxreadlen = _maxreadlen

    --// public methods of the object //--

    local handler = { }

    handler.id = function( )
        return id
    end
    handler.dispatch = function( )
        return dispatch
    end
    handler.disconnect = function( )
        return disconnect
    end
    handler.setlistener = function( listeners )
        dispatch = listeners.incoming
        disconnect = listeners.disconnect
    end
    handler.getstats = function( )
        return readtraffic, sendtraffic
    end
    handler.getsslinfo = function( )
        if ssl then
            return socket:info( )
        end
        return nil
    end
    handler.ssl = function( )
        return ssl
    end

    handler.kill = function( reason )
        disconnect( handler, reason or fatalerror or "closed" )    -- disconnect handler
        if not fatalerror and ( bufferqueuelen ~= 0 ) then
            send( socket, table_concat( bufferqueue, "", 1, bufferqueuelen ), 1, bufferlen )    -- forced send
        end
        _readlistlen = removesocket( _readlist, socket, _readlistlen )
        _sendlistlen = removesocket( _sendlist, socket, _sendlistlen )
        _socketlist[ socket ] = nil
        _writetimes[ handler ] = nil
        _activitytimes[ handler ] = nil
        _closelist[ handler ] = nil
        ratelimit_handshake_finished( handler )
        socket:close( )
        handler = nil
        socket = nil
        mem_free( )
        _ = server and server.remove( )
        ratelimit_release_ip( clientip )    -- Phase 7c F-NET-1: free per-IP slot
        out_put "server.lua: function 'wrapconnection': closed client handler and removed socket from lists"
    end
    handler.close = function( forced )
        out_put "server.lua: function 'wrapconnection': try to close client handler..."
        handler.readbuffer = return_false    -- dont read anymore
        handler.write = return_false    -- dont write anymore
        _activitytimes[ handler ] = nil   -- no activity check anymore
        if forced or ( bufferqueuelen == 0 ) then    -- close immediately
            _closelist[ handler ] = ( forced or "closed" )    -- cannot close the client at the moment, have to wait to the end of the cycle
        else    -- wait to empty bufferqueue
            _readlistlen = removesocket( _readlist, socket, _readlistlen )
            toclose = true
            out_put "server.lua: function 'wrapconnection': waiting for unsent data..."
        end
        return true
    end
    handler.ip = function( )
        return clientip
    end
    handler.clientip = handler.ip
    handler.clientport = function( )
        return clientport
    end
    handler.serverip = function( )
        return serverip
    end
    handler.serverport = function( )
        return serverport
    end
    local write = function( data )
        -- Phase 8 S4a: outbound transform pipeline runs at write
        -- time, not at send time. Once a stage has produced output
        -- bytes (e.g. zlib's deflate(Z_SYNC_FLUSH) for S4b) those
        -- bytes are committed - the partial-send retry path operates
        -- on the already-transformed wire bytes, which is the only
        -- way to keep stateful transforms (deflate) correct under
        -- partial sends. Default = passthrough = identity, so this is
        -- byte-for-byte equivalent to the legacy path.
        local wire = outframer:write( data )
        local n = string_len( wire )
        if n == 0 then
            return true
        end
        bufferlen = bufferlen + n
        if bufferlen > maxsendlen then
            handler.close( "send buffer exceeded" )
            return false
        elseif not _sendlist[ socket ] then
            _sendlistlen = _sendlistlen + 1
            _sendlist[ _sendlistlen ] = socket
            _sendlist[ socket ] = _sendlistlen
        end
        bufferqueuelen = bufferqueuelen + 1
        bufferqueue[ bufferqueuelen ] = wire
        _writetimes[ handler ] = _writetimes[ handler ] or _currenttime
        return true
    end
    handler.write = write
    handler.pattern = function( new )
        pattern = new or pattern
        return pattern
    end
    handler.bufferlen = function( readlen, sendlen )
        maxsendlen = sendlen or maxsendlen
        maxreadlen = readlen or maxreadlen
        return maxreadlen, maxsendlen
    end
    -- Phase 8 S4b: per-connection pipeline reshape accessors so the
    -- ADC dispatcher (hub_dispatch.lua) can splice an inflate stage
    -- ahead of the ADC-line stage on inbound ZON, and prepend a
    -- deflate stage on the outbound pipeline on outbound ZON. The
    -- inframer:prepend() reshape is the load-bearing semantic that
    -- S4a's iterator API was designed for - residual bytes the
    -- ADC-line stage had buffered after the ZON `\n` get re-fed
    -- through the new front (inflate) stage; see core/iostream.lua.
    handler.inframer_prepend = function( stage )
        return inframer:prepend( stage )
    end
    handler.outframer_prepend = function( stage )
        return outframer:prepend( stage )
    end
    -- Phase-9 follow-up (#192): splice a stage immediately before
    -- the terminal (the ADC-line framer). Used by BLOM HSND to put
    -- the counted-binary capture between inflate and adcline when
    -- ZLIF is active; for 1-stage pipelines it degenerates to
    -- prepend. The terminal's residual is drained synchronously
    -- through the new stage and any frames the terminal produces
    -- are parked in a per-pipeline deferred queue surfaced before
    -- the next _pull cycle - see `_newpipeline` in core/iostream.lua
    -- for the semantic.
    handler.inframer_insert_before_terminal = function( stage )
        return inframer:insert_before_terminal( stage )
    end

    local try_sending_on_write
    local try_reading_on_write
    local try_sending_on_read
    local try_reading_on_read

    local _readbuffer

    _readbuffer = function( )    -- this function reads data
        -- Phase 8 S1/S2: raw byte read instead of LuaSocket "*l". We
        -- no longer let LuaSocket cut lines for us; raw bytes go to
        -- the per-connection pipeline (inframer) whose terminal stage
        -- reassembles ADC frames across reads. receive( socket, n )
        -- with settimeout(0):
        -- IO_DONE returns up to n bytes; otherwise returns
        -- nil, errstr, <partial>, where errstr is "timeout" for
        -- plain-TCP nonblocking, "wantread"/"wantwrite" for the luasec
        -- TLS want-dance, or "closed"/other for a real failure
        -- (verified vs luasocket/src/buffer.c buffer_meth_receive).
        local buffer, err, part = receive( socket, maxreadlen )
        _activitytimes[ handler ] = _currenttime
        local data = buffer or part or ""
        local got = string_len( data )
        -- "benign" = the read did not fail terminally. "timeout" with no
        -- bytes is the normal nonblocking "nothing this tick" case and,
        -- unlike the old "*l" guard, must NOT close the connection (the
        -- old behaviour dropped any plain-TCP frame split across TCP
        -- segments - the latent "unwanted disconnects in big hubs" bug).
        local benign = ( err == nil ) or ( err == "timeout" ) or ( err == "wantread" ) or ( err == "wantwrite" )

        -- Process any bytes regardless of err. A final TCP segment can
        -- carry data AND the FIN, in which case LuaSocket returns
        -- nil,"closed",<final-bytes>. The old "*l" path never hit this
        -- (one line per call; the close arrived as a separate empty
        -- read) but with raw reads the data and the close coalesce -
        -- discarding the bytes here loses the last command (e.g. a
        -- +setpass sent immediately before the client closes).
        if got > 0 then
            local count = got * STAT_UNIT
            readtraffic = readtraffic + count

            try_reading_on_write = do_nothing
            try_reading_on_read = _readbuffer
            if ( err == "wantwrite" ) then    -- TLS want-dance, preserved verbatim
              try_reading_on_write = _readbuffer
              try_reading_on_read = do_nothing
              if not _sendlist[ socket ] then   -- add socket to writelist
                _sendlistlen = _sendlistlen + 1
                _sendlist[ _sendlistlen ] = socket
                _sendlist[ socket ] = _sendlistlen
              end
            end

            out_put( "server.lua: function 'wrapconnection': read data '", data, "', error: ", err )

            -- Phase 8 S4a: feed + lazy iterator. We pull frames one
            -- at a time so the ZON dispatcher (S4b) can call
            -- inframer:prepend( inflate_stage ) BEFORE the loop asks
            -- for the next frame. If we pulled all frames up front,
            -- the ADC-line stage would have already mis-parsed the
            -- post-ZON compressed suffix as plain ADC frames.
            inframer:feed( data )
            while true do
                local frame, overflow = inframer:next( )
                if overflow then
                    handler.close( "receive buffer exceeded" )
                    return false
                end
                if frame == nil then
                    break
                end
                -- The per-unit oversize cap is an ADC-line transport
                -- concern: that stage emits string frames. Non-string
                -- units (e.g. the HTTP framer's parsed-request /
                -- { reject } tables) carry their own hardening inside
                -- the stage and must not be string-length-checked here.
                if type( frame ) == "string" and string_len( frame ) > maxreadlen then    -- mirror old per-line cap: drop, don't dispatch
                    handler.close( "receive buffer exceeded" )
                    return false
                end
                dispatch( handler, frame, err )
                -- If processing this frame closed the connection (e.g.
                -- invalid-SID kill -> handler.close), stop: do not
                -- process further pipelined frames on a closing handler.
                -- handler.close() sets handler.readbuffer = return_false
                -- synchronously, so that is the live guard. The
                -- `not handler` check is purely defensive (the actual
                -- handler = nil teardown happens later in tick()).
                if not handler then
                    return false
                end
                if handler.readbuffer == return_false then
                    return true
                end
            end
        elseif benign then
            -- No bytes and no terminal error: keep the read wiring sane
            -- and wait for the next tick.
            try_reading_on_write = do_nothing
            try_reading_on_read = _readbuffer
        end

        if benign then
            return true
        else    -- terminal error / close: any final data dispatched above
            out_put( "server.lua: function 'wrapconnection': client ", clientip, ":", clientport, " error: ", err )
            fatalerror = err or "fatal error"
            handler.close( fatalerror )
            return false
        end
    end

    local _sendbuffer

    _sendbuffer = function( )    -- this function sends data
        local buffer = table_concat( bufferqueue, "", 1, bufferqueuelen )
        local succ, err, byte = send( socket, buffer, 1, bufferlen )
        local count = ( succ or byte or 0 ) * STAT_UNIT
        sendtraffic = sendtraffic + count
        _ = _cleanqueue and clean( bufferqueue )
        out_put( "server.lua: function 'wrapconnection': sent '", buffer, "', bytes: ", succ, ", error: ", err, ", part: ", byte, ", to: ", clientip, ":", clientport )
        if succ then    -- sending succesful
            bufferqueuelen = 0
            bufferlen = 0
            if toclose then
                handler.close( "regular close" )
                return true
            end
            _writetimes[ handler ] = nil
            _activitytimes[ handler ] = _currenttime
            try_sending_on_write = _sendbuffer
            try_sending_on_read = do_nothing
            return true
        elseif byte and ( err ~= "closed" ) then    -- sending not finished yet
            buffer = string_sub( buffer, byte + 1, bufferlen )    -- new buffer
            bufferqueue[ 1 ] = buffer    -- insert new buffer in queue
            bufferqueuelen = 1
            bufferlen = bufferlen - byte
            _writetimes[ handler ] = _currenttime
            if ( err ~= "wantread" ) then
              if not _sendlist[ socket ] then   -- add socket to sendlist again
                _sendlistlen = _sendlistlen + 1
                _sendlist[ _sendlistlen ] = socket
                _sendlist[ socket ] = _sendlistlen
              end
              try_sending_on_write = _sendbuffer
              try_sending_on_read = do_nothing
            else  -- "wantread"...
              try_sending_on_write = do_nothing
              try_sending_on_read = _sendbuffer
            end
            return true
        else    -- connection was closed during sending or fatal error
            out_put( "server.lua: function 'wrapconnection': client ", clientip, ":", clientport, " error: ", err )
            fatalerror = err or "fatal error"
            handler.close( fatalerror )
            return false
        end
    end

    -- default behaviour

    try_sending_on_write = _sendbuffer
    try_reading_on_write = do_nothing
    try_sending_on_read = do_nothing
    try_reading_on_read = _readbuffer

    local handle_write_event = function( )
      _sendlistlen = removesocket( _sendlist, socket, _sendlistlen )    -- delete socket from writelist in any case
      try_sending_on_write( )
      try_reading_on_write( )
    end

    local handle_read_event = function( )
      try_sending_on_read( )
      try_reading_on_read( )
    end

    if sslctx then    -- ssl?
        ssl = true
        local wrote
        ratelimit_handshake_started( handler )    -- Phase 7c F-NET-2: handshake-deadline tracking
        local handshake = coroutine_wrap( function( client )    -- create handshake coroutine
                local err
                -- #207: reduced from 20 to 10. The loop only iterates
                -- on the SSL wantread/wantwrite I/O dance, not on any
                -- new cryptographic work - a well-behaved TLS 1.3 peer
                -- completes the dance in 2-3 yields. A buggy / slow
                -- peer gets 10 chances before forced close, which is
                -- still generous (the `ratelimit_handshake_timeout`
                -- wallclock deadline at 10s default catches stuck
                -- handshakes separately). 20 was historical; the
                -- ECDH-cost-per-attempt concern in the #207 report is
                -- wrong - the per-handshake ECDH happens once on the
                -- FIRST flight, subsequent iterations are framing.
                for i = 1, 10 do    -- handshake attempts
                    _, err = client:dohandshake( )
                    if not err then
                        out_put( "server.lua: function 'wrapconnection': ssl handshake done" )
                        ratelimit_handshake_finished( handler )    -- Phase 7c F-NET-2
                        _sendlistlen = ( wrote and removesocket( _sendlist, socket, _sendlistlen ) ) or _sendlistlen
                        handler.readbuffer = handle_read_event   -- when handshake is done, replace the handshake function with regular functions
                        handler.sendbuffer = handle_write_event
                        --return dispatch( handler )
                        return true
                    else
                        out_put( "server.lua: function 'wrapconnection': error during ssl handshake: ", err )
                        if err == "wantwrite" then
                          if not wrote then
                            _sendlistlen = _sendlistlen + 1
                            _sendlist[ _sendlistlen ] = client
                            wrote = true
                          end
                        elseif err == "wantread" then
                            if wrote then
                              _sendlistlen = removesocket( _sendlist, socket, _sendlistlen )
                              wrote = false
                            end
                        else
                          break
                        end
                        --coroutine_yield( handler, nil, err )    -- handshake not finished
                        coroutine_yield( )
                    end
                end
                err = err or "?"
                fatalerror = "max handshake attemps exceeded (last error: " .. tostring( err ) .. ")"
                handler.close( fatalerror )    -- forced disconnect
                return false    -- handshake failed
            end
        )
        if startssl then    -- ssl now?
            out_put( "server.lua: function 'wrapconnection': starting ssl handshake" )
            local err
            socket, err = ssl_wrap( socket, sslctx )    -- wrap socket
            if err then
                out_put( "server.lua: function 'wrapconnection': ssl error: ", err )
                mem_free( )
                return nil, nil, err    -- fatal error
            end
            socket:settimeout( 0 )
            handler.readbuffer = handshake
            handler.sendbuffer = handshake
            handshake( socket )    -- do handshake
        else
            handler.readbuffer = handle_read_event
            handler.sendbuffer = handle_write_event
        end
    else    -- normal connection
      ssl = false
      handler.readbuffer = handle_read_event
      handler.sendbuffer = handle_write_event
    end

    send = socket.send
    receive = socket.receive

    _socketlist[ socket ] = handler
    _readlistlen = _readlistlen + 1
    _readlist[ _readlistlen ] = socket
    _readlist[ socket ] = _readlistlen

    -- Arm the idle sweep at accept. Previously _activitytimes[handler]
    -- was set only on the first read with bytes (_readbuffer, got>0),
    -- so a connection that completes TCP accept and then sends NOTHING
    -- was never swept (held until the client closes - a slowloris /
    -- fd-exhaustion vector, especially on the no-handshake HTTP
    -- listener). Initialising here bounds every connection by the
    -- standard _max_idle_time regardless of listener type.
    _activitytimes[ handler ] = _currenttime

    return handler, socket
end


do_nothing = function( )
end

return_false = function( )
    return false
end

removesocket = function( list, socket, len )    -- this function removes sockets from a list (copied from copas)
    local pos = list[ socket ]
    if pos then
        list[ socket ] = nil
        local last = list[ len ]
        list[ len ] = nil
        if last ~= socket then
            list[ last ] = pos
            list[ pos ] = last
        end
        return len - 1
    end
    return len
end

closesocket = function( socket )
    _sendlistlen = removesocket( _sendlist, socket, _sendlistlen )
    _readlistlen = removesocket( _readlist, socket, _readlistlen )
    _socketlist[ socket ] = nil
    socket:close( )
    mem_free( )
end

----------------------------------// PUBLIC //--

addserver = function( p ) -- listeners, port, addr, pattern, sslctx, maxconnections, startssl, family )    -- this function provides a way for other scripts to reg a server
    local err
    out_put( "server.lua: function 'addserver': autossl on ", p.port, " is ", p.startssl )
    if type( p.listeners ) ~= "table" then
        err = "invalid listener table"
    end
    -- #186: the first clause was `not type( p.port ) == "number"`,
    -- which parses as `(not type(p.port)) == "number"` -> always
    -- false, so the type check was dead and only the range check ran
    -- (and it accepted port 0 = OS-assigned ephemeral). Fixed to a
    -- real integer-in-1..65535 check.
    if type( p.port ) ~= "number" or p.port % 1 ~= 0 or not ( p.port >= 1 and p.port <= 65535 ) then
        err = "invalid port"
    elseif _server[ _serverkey( p.port, p.family ) ] then
        err =  "listeners on port '" .. p.port .. "' (" .. ( p.family or "ipv4" ) .. ") already exist"
    elseif p.sslctx and not luasec then
        err = "luasec not found"
    end
    if err then
        out_error( "server.lua: function 'addserver': ", err )
        return nil, err
    end
    -- #186: addserver binds p.addr and never read p.ip, but every
    -- ADC listener in hub.lua passes the hub_listen address as `ip`.
    -- Result: hub_listen was silently ignored and the hub ALWAYS
    -- bound 0.0.0.0 / in6addr_any regardless of an operator's
    -- explicit bind restriction (exposure). Honour `ip` as the bind
    -- address; explicit `addr` still wins (e.g. the loopback-pinned
    -- HTTP listener); default "*" (bind-all) is unchanged so the
    -- default hub_listen = { "*" } config behaves exactly as before.
    p.addr = p.addr or p.ip or "*"
    local server, err
    -- The IPv6 socket here is created via luasocket.tcp6(), which in
    -- the bundled luasocket (see luasocket/src/inet.c inet_trycreate)
    -- forces IPV6_V6ONLY = 1 unconditionally. That keeps the v6
    -- listener from also accepting v4-mapped traffic, which would
    -- collide with the v4 socket bound to the same port. Do NOT
    -- replace this with a defensive Lua-side setoption("ipv6-v6only",
    -- true) call - that option name is luasocket-specific and would
    -- silently fail on older / forked builds, producing a worse
    -- failure shape than the C-side default. The dual-stack-leak
    -- concern is what makes the (port, family) registry key
    -- meaningful in the first place; see _serverkey comment above.
    if p.family == "ipv6" then
        server, err = luasocket.tcp6( )
    else
        server, err = luasocket.tcp4( )
    end
    if err then
        out_error( "server.lua: function 'addserver', luasocket cannot create master obejct: ", err )
        return nil, err
    end
    -- Set SO_REUSEADDR BEFORE bind (Linux only - see _is_windows above).
    -- On Linux the option only takes effect on the next bind() call;
    -- setting it after bind is a no-op and a fast restart hits "address
    -- already in use" if the previous listener left the port in
    -- TIME_WAIT. Surfaced by the #128 plaintext-mode smoke test which
    -- stops + restarts the hub against the same staging tree. Pre-existing
    -- latent bug; the post-bind setoption stays for completeness but the
    -- pre-bind one is what actually unblocks the rebind. Deliberately
    -- SKIPPED on Windows so a same-port second bind fails visibly instead
    -- of silently succeeding (SO_REUSEADDR = SO_REUSEPORT there).
    if not _is_windows then
        local _, prebind_err = server:setoption( "reuseaddr", true )
        if prebind_err then
            out_error( "server.lua: function 'addserver', luasocket socket pre-bind setoption: ", prebind_err )
            return nil, prebind_err
        end
    end
    local num, err = server:bind( p.addr, p.port )
    if err then
        out_error( "server.lua: function 'addserver', luasocket socket bind: ", err )
        return nil, err
    end
    local num, err = server:listen( )
    if err then
        out_error( "server.lua: function 'addserver', luasocket socket listen: ", err )
        return nil, err
    end
    local addr, port = server:getsockname( )
    local handler, err = wrapserver( p.listeners, server, addr, port, p.family, p.pattern, p.sslctx, p.maxconnections, p.startssl )    -- wrap new server socket
    if not handler then
        server:close( )
        return nil, err
    end
    server:settimeout( 0 )
    -- reuseaddr on the bound socket is Linux-only for the same reason as
    -- the pre-bind call above: on Windows it would re-open the port to
    -- being hijacked by another process. keepalive is set on every
    -- platform.
    local err
    if not _is_windows then
        _, err = server:setoption( "reuseaddr", true )
    end
    local _, err2 = server:setoption( "keepalive", true )
    if err or err2 then
        out_error( "server.lua: function 'addserver', luasocket socket setoption: ", err or err2 )
        return nil, err or err2
    end
    _readlistlen = _readlistlen + 1
    _readlist[ _readlistlen ] = server
    _server[ _serverkey( port, p.family ) ] = handler
    _socketlist[ server ] = handler
    out_put( "server.lua: function 'addserver': new server listener on '", addr, ":", port, "'" )
    return handler
end

killall = function( )
    local tmp = { }
    for socket, handler in pairs( _socketlist ) do
        tmp[ socket ] = handler
    end
    for socket, handler in pairs( tmp ) do
        handler.kill( )
        _socketlist[ socket ] = nil
    end
    _readlistlen = 0
    _sendlistlen = 0
    _timerlistlen = 0
    _server = { }
    _readlist = { }
    _sendlist = { }
    _timerlist = { }
    _socketlist = { }
    mem_free( )
end

addtimer = function( listener )
    if ( type( listener ) ~= "function" ) and ( type( listener ) ~= "thread" ) then
        return nil, "invalid listener type '" .. type( listener ) .. "'"
    end
    _timerlistlen = _timerlistlen + 1
    _timerlist[ _timerlistlen ] = listener
    return true
end

tick = function( )
    local read, write, err = socket_select( _readlist, _sendlist, _selecttimeout )
    for i, socket in ipairs( write ) do    -- send data waiting in writequeues
        local handler = _socketlist[ socket ]
        if handler then
            handler.sendbuffer( )
        else
            closesocket( socket )
            out_put "server.lua: function 'tick': found no handler and closed socket (writelist)"    -- this should not happen
        end
    end
    for i, socket in ipairs( read ) do    -- receive data
        local handler = _socketlist[ socket ]
        if handler then
            handler.readbuffer( )
        else
            closesocket( socket )
            out_put "server.lua: function 'tick': found no handler and closed socket (readlist)"    -- this can happen
        end
    end
    _currenttime = os_time( )
    if os_difftime( _currenttime, _timer ) >= 1 then
        local dead = { }
        for i = 1, _timerlistlen do
            local timer = _timerlist[ i ]
            if type( timer ) == "thread" then
                local status = coroutine.status( timer )
                if status == "dead" then
                    dead[ i ] = true
                elseif status ~= "running" then
                    coroutine.resume(timer)
                end
            elseif timer then
                -- `_timerlistlen` is captured once as the numeric-for
                -- bound; if a timer callback clears the timer list
                -- mid-loop (killall() on graceful shutdown sets
                -- `_timerlist = {}`), the remaining slots read nil. Skip
                -- them instead of calling nil (teardown-time crash).
                timer( )
            end
        end
        for i = _timerlistlen, 1, -1 do -- remove dead coroutines; don't use swap and pop to preserve order of timers (see http://lua-users.org/lists/lua-l/2013-11/msg00031.html)
            if dead[ i ] then
                table.remove( _timerlist, i )
                _timerlistlen = _timerlistlen - 1
            end
        end
        _timer = _currenttime
    end
    for handler, err in pairs( _closelist ) do
        handler.kill( err )    -- close, kill, delete handler/socket
    end
    clean( _closelist )
    socket_sleep( _sleeptime )    -- wait some time
end

----------------------------------// BEGIN //--

_timer = os_time( )
_starttime = os_time( )

addtimer( function( )
        local difftime = os_difftime( _currenttime, _starttime )
        if difftime >= _checkinterval then
            _starttime = _currenttime
            for handler, timestamp in pairs( _writetimes ) do
                if os_difftime( _currenttime, timestamp ) >= _sendtimeout then
                    handler.close( "timeout" )    -- forced disconnect
                end
            end
            for handler, timestamp in pairs( _activitytimes ) do
                if os_difftime( _currenttime, timestamp ) >= _max_idle_time then
                    handler.close( "timeout" )    -- forced disconnect
                end
            end
            ratelimit_tick( )    -- prune stale token buckets
        end
    end
)

-- #207: dedicated faster sweep for stuck TLS handshakes. Runs
-- every ratelimit_handshake_sweep_interval seconds (default 10s)
-- instead of being gated by the 120s _checkinterval. Reduces the
-- worst-case lifetime of a stuck handshake's handler + coroutine
-- from ~130s to ~20s under the default handshake timeout of 10s.
-- The cadence is read live here - once per timer tick, which the
-- loop caps at 1/sec - rather than cached at module-load, so
-- PUT /v1/config / cfg.set apply a new value without a hub restart
-- (its apply_status is "live"; #648 follow-up). The cfg validator
-- only type-checks this key, so the `< 1` clamp is what enforces the
-- >= 1 floor - a 0 or negative value would otherwise busy-loop the
-- sweep every tick.
_hs_sweep_last = os_time( )
addtimer( function( )
        local sweep_interval = tonumber( cfg_get "ratelimit_handshake_sweep_interval" ) or 10
        if sweep_interval < 1 then sweep_interval = 1 end
        if os_difftime( _currenttime, _hs_sweep_last ) < sweep_interval then
            return
        end
        _hs_sweep_last = _currenttime
        local expired = ratelimit_expired_handshakes( )
        if expired then
            for _, h in ipairs( expired ) do
                h.close( "handshake timeout" )
            end
        end
    end
)

----------------------------------// PUBLIC INTERFACE //--

return {

    tick = tick,
    killall = killall,
    addtimer = addtimer,
    addserver = addserver,

}
