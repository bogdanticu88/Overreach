# Contributing to Overreach

Thanks for your interest. Overreach is early, and the most useful contributions
right now are new attack patterns, better effect inference, and fixes from
running it on real specs.

## Ground rules

- Open an issue before a large change, so we can agree the approach.
- Keep the core small and readable. Parsers, model providers and output formats
  are the edges; the model, chains and breaker are the core.
- Every change keeps the type check and tests green:
  ```bash
  pip install -e ".[dev]"
  python -m pytest -q
  python -m mypy src/overreach
  ```
- New attack classes come with a test: add a fixture that the finder must catch,
  the way `tests/attacks/` does.
- Never add code that executes or fetches anything from an input spec. Overreach
  is built to be safe to point at hostile input; see `SECURITY.md`.

## Sign-off (DCO)

Every commit must be signed off under the
[Developer Certificate of Origin](https://developercertificate.org/): add a
`Signed-off-by: Your Name <you@example.com>` line, which `git commit -s` does for
you. This certifies you wrote the change or have the right to submit it.

## Licensing of contributions

Overreach is licensed under AGPL-3.0 (see `LICENSE`). A separate commercial
edition and hosted service are also offered. By contributing, you agree that
your contributions may be included in both: you grant the maintainer a
perpetual, irrevocable licence to use, modify, and relicense your contribution,
including under a commercial licence, while your contribution also remains
available under AGPL-3.0. You keep the copyright to your work.

If you cannot agree to that, open an issue and we will find another way to take
the idea (for example, you describe it and someone else implements it).

## Security issues

Do not open a public issue for a security problem in Overreach itself. Follow
`SECURITY.md`.
