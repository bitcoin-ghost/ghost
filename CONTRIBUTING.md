# Contributing to Bitcoin Ghost

Contributions are welcome. This is Bitcoin infrastructure -- correctness matters more than speed.

## Development Setup

### Requirements

- Rust 1.75+ (stable toolchain)
- Git with submodule support
- SQLite3 development headers
- Linux recommended (Ubuntu 22.04+)

### Clone and Build

```bash
git clone --recurse-submodules https://github.com/bitcoin-ghost/ghost.git
cd ghost
cargo build --workspace
```

If you already cloned without submodules:

```bash
git submodule update --init --recursive
```

## Code Style

All code must pass these checks before submission:

```bash
cargo fmt --all
cargo clippy --workspace -- -D warnings
```

Zero warnings policy. If clippy complains, fix it.


## Testing

All tests must pass:

```bash
cargo test --workspace
```

For specific crates:

```bash
cargo test -p ghost-pool --lib
cargo test -p ghost-verification
```

Do not submit PRs with failing tests.

## Pull Request Process

1. Fork the repository
2. Create a feature branch from `main`
3. Make your changes with clean, passing tests
4. Run `cargo fmt`, `cargo clippy`, and `cargo test`
5. Submit a PR against `main`

Keep PRs focused. One logical change per PR. Large refactors should be discussed in an issue first.

## Commit Messages

Follow the conventional commit style used in this project:

```
fix: Resolve share calculation overflow on high difficulty
feat: Add archive mode verification challenges
docs: Update node operator setup guide
chore: Bump dependency versions
refactor: Simplify payout distribution logic
```

- Use imperative mood ("Add feature" not "Added feature")
- Keep the first line under 72 characters
- Reference issue numbers where applicable

## What Not to Do

- Do not reference any tools, assistants, or automation in commits or PR descriptions
- Do not submit half-implemented features or placeholder code
- Do not add `TODO` or `FIXME` comments without a corresponding issue
- Do not modify the MPC ceremony code without thorough review

## Security Vulnerabilities

**Do NOT open public issues for security vulnerabilities.**

Report security issues to: **security@bitcoinghost.org**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You will receive a response within 48 hours.

## Architecture

Before making changes, read [docs/protocols/ARCHITECTURE.md](docs/protocols/ARCHITECTURE.md) to understand the system design. Key areas:

- `bins/ghost-pool/` -- Main pool binary (mining, consensus, payouts)
- `crates/` -- Library crates (consensus, verification, storage, etc.)
- `ghost-core/` -- Bitcoin Core fork (separate build system)

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
