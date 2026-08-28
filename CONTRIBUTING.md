# Contributing to luadch

Thanks for wanting to contribute. This page covers the things that are easy to
get wrong from the outside. The engineering how-to (core modules, plugins,
testing, security checklists, Definition of Done) lives in
[`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md).

## Open pull requests against `dev`, not `master`

GitHub offers `master` by default because it is the repository's default
branch - but `master` is the release substrate and only receives changes that
have already been validated. New work goes to `dev` first.

| Branch | What it is | Target it? |
|---|---|---|
| **`dev`** | Staging. Everything lands here first and is validated on a test hub (`ghcr.io/luadch-ng/luadch-ng:dev` is rebuilt on every push). | **Yes - this one** |
| `master` | Release substrate for the 3.2.x line. Promoted from `dev` once validated; release tags are cut here. | No (maintainers) |
| `release/3.1.x` | Maintenance line, critical security backports only. | No (maintainers) |

If you already opened a PR against `master`, nothing is lost - a maintainer
can retarget it to `dev` in one click, and it stays your PR with your
authorship intact. No need to close and reopen it.

**Found a security vulnerability?** Do not open a public issue or PR - see
[`docs/SECURITY.md`](docs/SECURITY.md) for the reporting process.

## Before opening the PR

- **Build it.** [`docs/BUILDING.md`](docs/BUILDING.md) has the Linux, Windows
  and ARM recipes.
- **Run the tests.** [`tests/README.md`](tests/README.md) - a Lua unit suite
  plus a protocol-level smoke harness. Both run in CI on Linux *and* Windows
  for every PR, so running them locally first saves a round trip.
- **One logical change per PR**, referencing the issue it addresses. Unrelated
  fixes belong in separate PRs - it keeps review honest and makes reverts
  surgical.
- **Match the surrounding code.** Lua style follows the file you are editing.
  Comments explain *why*, not *what*. Avoid drive-by refactors: if you spot
  something unrelated, open an issue instead.
- **Bug fixes should come with a test** that fails before the fix and passes
  after. The exception is a diff that is self-evidently its own proof (a typo,
  dead code, a redundant call). See
  [`docs/DEVELOPMENT.md` §4](docs/DEVELOPMENT.md).

## Where things live

- **`core/*.lua`** - the hub itself. It runs in a restricted environment where
  every global must be imported (`local X = use "X"`); a bare global passes
  unit tests but fails at hub boot. Read
  [`docs/DEVELOPMENT.md` §2](docs/DEVELOPMENT.md) before touching core.
- **`scripts/*.lua`** - bundled plugins, running in a sandbox.
  [`docs/PLUGIN_API.md`](docs/PLUGIN_API.md) is the API reference;
  [`docs/DEVELOPMENT.md` §3](docs/DEVELOPMENT.md) adds the conventions on top
  of it.
- **Additional plugins** that do not ship with the hub live in the companion
  repo [`luadch-ng/scripts`](https://github.com/luadch-ng/scripts).
- **`tests/`** - unit tests (`tests/unit/`) and the smoke harness
  (`tests/smoke/run.py`).

## Translating

You do not need to touch code to help. luadch is translated on Weblate at
[translate.dcvault.net](https://translate.dcvault.net/) - pick the `luadch-ng`
project and your language. Translations flow back into the repo automatically;
see [`docs/TRANSLATING.md`](docs/TRANSLATING.md) for the how-to and the rules
(keep `%s` placeholders, keep DC jargon in English).

## Reporting bugs

Open an issue with the hub version (`+hubinfo` output or the boot line in
`log/event.log`), the platform, and what you did to trigger it. Log excerpts
from `log/error.log` help. If the report is about an older release, say which
one - a good share of reports turn out to be already fixed on the current
line.

## License

Contributions are made under the project's [GPL-3.0](LICENSE) license.
