# Translating luadch

luadch's user-facing strings are translated on Weblate:

**➡️ [translate.dcvault.net](https://translate.dcvault.net/)**

No account setup on your side beyond registering on that instance - just
pick the `luadch` project and start. This page explains how translating
works and how your translations reach the hub.

- [How it works](#how-it-works)
- [How to translate](#how-to-translate)
- [The flow: from Weblate to a release](#the-flow-from-weblate-to-a-release)
- [Adding a new language](#adding-a-new-language)

## How it works

The **Git repository is the source of truth**; Weblate is a bidirectional
mirror on top of it. You never upload files, and you never edit the JSON by
hand - Weblate owns the language files and would overwrite a manual change.

- **English** is the source, authored by maintainers in the repo
  (`lang/en/hub.json` for the hub, `scripts/lang/en/<plugin>.json` per
  plugin). Weblate pulls it automatically.
- **Every other language** is edited in the Weblate web UI. Weblate pushes
  the result back to the repo, where a maintainer merges it.

**English fallback - translations may be incomplete.** Every string is read
as `lang.key or "<English>"`, so an untranslated (or empty) string falls back
to English at runtime. A translation is useful and shippable at any
percentage; a missing string is never a blank message, just English.

## How to translate

1. Open **[translate.dcvault.net](https://translate.dcvault.net/)**, register
   / log in, and pick the `luadch` project and your language (or
   [add one](#adding-a-new-language)).
2. Translate string by string in the web UI. Two rules keep translations
   safe:
   - **Keep every placeholder, in the same order.** `%s` (text) and `%d`
     (number) are filled in at runtime by Lua's `string.format`, which has
     **no positional specifiers** (`%1$s` does not exist and would crash) -
     the placeholders are filled in the order they appear. So keep the same
     number, the same types, and the same order as the English source; if a
     message needs an extra value it is appended at the end. Weblate warns
     you about placeholder mismatches.
   - **Keep DC / ADC jargon in English**, even mid-sentence: *Hub, Slot,
     Share, OP, Kick, Ban, Nick, CID, PID, PM, TLS, ZLIF*. Users expect these
     terms in English.
3. Leave a string untranslated rather than guessing - English fallback beats
   a wrong translation.

That's it. Saving in Weblate is all that is required from a translator.

## The flow: from Weblate to a release

```
   maintainers author EN ──push──▶ dev ──webhook──▶ Weblate
                                    ▲                   │  translators translate
   you merge the PR ◀── weblate branch ◀── Weblate pushes back
```

- Weblate pulls English source from `dev` and pushes translations to a
  dedicated **`weblate`** branch (never straight to `dev`).
- The `weblate-funnel` workflow (weekly + on demand) opens/updates a
  `weblate` -> `dev` pull request, but funnels **only real translations**: a
  language that was added but not yet translated (all-empty), and files Weblate
  only reformatted, are filtered out, so empty language skeletons never reach
  `dev`. It gates every imported language before opening the PR (English
  complete and consistent with the code, no orphan keys, and each translated
  string keeps its `%s` / `%d` placeholder signature - same conversion types in
  the same order).
- A maintainer reviews and merges that pull request (squash), so translations
  pass the same review as code.
- After the funnel PR merges, the `weblate-reset` workflow resets Weblate's own
  git branch back to `dev`. Weblate commits every translation separately, so its
  branch is permanently ahead of `dev`; left alone that divergence grows until
  Weblate can no longer merge the next `dev` change and auto-locks ("Could not
  merge the repository"). The reset runs **only when it is safe** - it refuses
  unless all three states of Weblate content are clear: no uncommitted units
  (`needs_commit`), nothing committed-but-unpushed (`needs_push`), and the funnel
  a no-op (nothing committed-and-pushed left to bring across), all checked under
  the component lock - so no translation is ever discarded. It ships dormant (dry
  run, logging its decision); set the repo variable `WEBLATE_AUTORESET_APPLY=1`
  to arm it. When disarmed, clear the divergence manually: reset Weblate to `dev`
  from the container after a funnel lands (`git reset --hard origin/dev` in the
  component checkout, then `create_translations(force=True)` in the Weblate shell).

> **Translate in Weblate, not in `dev`.** Weblate is the source of truth for
> translations; the funnel overwrites a `dev` language file with Weblate's
> whenever their real content differs, so a hand-edit made directly in `dev`
> will be clobbered on the next funnel run. Fix translations in Weblate.
- From `dev` translations ride the normal `dev` -> `master` promotion; there
  is no separate translation release. A hub upgrade ships whatever
  translations exist at that point.

## Adding a new language

In Weblate, open a component and use **Tools -> Start new translation**, pick
the language (e.g. French / `fr`). Weblate creates `lang/fr/hub.json` and
`scripts/lang/fr/<plugin>.json`. No hub code change is needed: the loader
builds the path from `cfg.language`, so once the `fr` files exist an operator
just sets `language = "fr"` in `cfg.tbl`, and untranslated strings fall back
to English.
