# Contributing to Keymate

Bug reports, ideas and pull requests are welcome: for anything big, open an
issue first.

## Build and run

You need macOS, [Rust](https://rustup.rs), and the tools Keymate uses: the
shared ones, plus each service's own tool (the GitHub CLI for GitHub):

```sh
brew install openssh libfido2 git gh
cargo run -- doctor --deps-only
```

Before sending a pull request:

```sh
cargo test
cargo clippy --all-targets -- -D warnings
```

By contributing, you agree your work is licensed under the Apache License 2.0,
like the rest of Keymate.

## Layout

| | |
|---|---|
| `src/` | Checks, devices and updates, usable by a future app (`lib.rs`) |
| `src/github/` | GitHub: setup, status, signer and nuke |
| `src/main.rs`, `src/cli/` | The `keymate` command: arguments, prompts and output |
| `Formula/keymate.rb` | The Homebrew formula (this repository is its own tap) |

The README's GIFs (`docs/`) show the real CLI on made-up data: a fake security
key and service account. They're recorded with [VHS](https://github.com/charmbracelet/vhs),
with tooling that isn't in the repository.

## Adding a service

Keymate is meant to support more services than GitHub. Every command takes a service the same way, so a new one fits in
without changing how Keymate looks or works:

1. Add it to `Service` and `Service::ALL` (`src/service.rs`) and to the CLI's
   `ServiceArg` (`src/cli/mod.rs`). Every command's service menu lists it from
   then on.
2. Give it its checks in `src/doctor.rs`: its own tools and the sign-in.
3. Implement setup, status, signer and nuke for it in its own module, following
   GitHub's (`src/github/`, with its prompts in `src/cli/`). Keep the
   same layout: what Keymate found, the questions, the plan, then a `✓` line
   per change.
4. Add its tools to `Formula/keymate.rb`, and a row to the README's services
   table.

## Releasing

With [cargo-release](https://github.com/crate-ci/cargo-release)
(`brew install cargo-release`), from a clean, pushed `main`:

```sh
cargo release minor             # dry run: shows what it would do
cargo release minor --execute   # patch, minor or major
```

It bumps the shared `version` in `Cargo.toml` and `Cargo.lock`, commits
`chore: release <version>`, tags `v<version>` and pushes both. The commit and
tag are signed.

`.github/workflows/release.yml` only runs for a tag signed with a key in
`.github/allowed_signers`. It checks the tag matches `Cargo.toml`, builds the
Apple silicon binary, publishes the release and points
`Formula/keymate.rb` at it. It pushes that change to `main`, so if `main` is
protected, let GitHub Actions push to it.

### Release signing keys

`.github/allowed_signers` lists the keys allowed to sign release tags, one per
line: `<email> <key type> <public key>`. To allow a new key, append its public
key (without the comment at the end of the `.pub` file):

```sh
echo "<email> $(cut -d' ' -f1,2 ~/.ssh/<your-key>.pub)" >> .github/allowed_signers
```

Remove a key's line once you no longer sign with it.

For SSH-signed tags, git looks up the tagger's email in this file, so this
repository's `user.email` must match the email on the key's line:

```sh
git config user.email "<email>"
```

Check a tag locally before pushing it:

```sh
git -c gpg.ssh.allowedSignersFile=.github/allowed_signers verify-tag v0.2.0
```
