# Contributing to subsift

Thanks for helping sift the noise! Contributions of every size are welcome —
especially **new patterns**, which is where the tool gets smarter over time.

## Quick start

```bash
git clone https://github.com/Dry1ceD7/subsift
cd subsift
python3 tests/test_subsift.py     # run the checks (no deps needed)
python3 subsift.py examples/sample.txt --interesting --stats
```

subsift is **pure standard library, single file, no dependencies** — please keep
it that way. If a change would add a dependency, let's discuss it in an issue first.

## The easiest (and most valuable) contribution: patterns

All the classification lives in plain dicts at the top of [`subsift.py`](subsift.py):

- `ENV_TOKENS` — labels that mark an environment (`dev`, `staging`, `uat`, …)
- `CATEGORIES` — keywords that map a host to a category (`admin`, `auth`, `api`, …)
- `CAT_WEIGHT` — how much each category counts toward the interest score
- `NOISE_RULES` / `COLLAPSE_RE` — patterns for junk to drop or collapse
- `SUFFIXES` — public suffixes, so ccTLDs aren't mistaken for tokens

Ran subsift on a target and saw a host mis-tagged, missed, or wrongly dropped?
That's a pattern gap — a perfect PR:

1. Add the token/keyword/rule to the right dict.
2. Add a one-line case to `tests/test_subsift.py` proving it.
3. Open the PR with the hostname that motivated it (redact the real target if needed).

## Pull requests

- Keep changes focused; one idea per PR.
- Run `python3 tests/test_subsift.py` before pushing — CI runs it on 3.9/3.11/3.13.
- New behavior gets a test. New patterns get a test case.
- Be kind in reviews and issues. 🙂

## Scope

subsift only reads and classifies hostnames — it makes **no network requests** and
never will. Anything that reaches out over the network belongs in a different tool.

## License

By contributing you agree your work is licensed under the project's [MIT License](LICENSE).
