# Keymate

[![CI](https://github.com/blturan/keymate/actions/workflows/ci.yml/badge.svg)](https://github.com/blturan/keymate/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/blturan/keymate?color=blue)](https://github.com/blturan/keymate/releases/latest)
[![macOS · Apple silicon](https://img.shields.io/badge/macOS-Apple%20silicon-black?logo=apple)](#install)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

**Set up and manage your hardware security keys.**

Plug in a FIDO2 security key, pick a service, and Keymate
sets the key up for it. It creates a key that stays on your hardware, registers
it with the service, tests it, and configures your Mac. It shows a plan and asks
before every change.

Keymate starts with **GitHub**: SSH access and commit signing. More services
will follow, and suggestions are welcome: [open an issue](https://github.com/blturan/keymate/issues).

> Early prototype, so far only tested on macOS with a YubiKey.

## Why Keymate

A normal SSH key is a file on your Mac. Anyone who copies that file can use it
from anywhere. A key on a security key can't be copied, it stays on the device,
and every use needs the key plugged in and a touch.

Setting this up by hand takes a while; create the key, add it to GitHub, edit
your SSH and Git config, then test it. Keymate does it in one run in seconds. Replacing a key, adding a backup or moving to a new Mac works the same
way.

## Demo

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/demo-dark.gif">
    <img src="docs/demo-light.gif" width="720" alt="Setting up a YubiKey with keymate setup: choosing a service, the questions, the plan and the result">
  </picture>
</p>

## Install

Keymate needs a Mac with Apple silicon.

```sh
brew tap blturan/keymate https://github.com/blturan/keymate
brew trust --formula blturan/keymate/keymate
brew install keymate
```

Homebrew only loads formulae from taps outside its own once you trust them,
which is what `brew trust` does.

Homebrew also installs what Keymate needs: OpenSSH (with security-key support),
libfido2 and Git, plus each service's own tool, such as the GitHub CLI. To check
they're all there:

```sh
keymate doctor --deps-only
```

## Get started

Plug in **one** security key and run setup. Keymate asks which service you mean,
or name it yourself:

```sh
keymate setup
```

For a backup key, plug in only the other key and run setup again. Each key gets
its own credential, so either one works.

## Commands

Commands that work with a service take its name, e.g. `keymate status github`.
Leave it out and Keymate asks.

| Command | What it does |
| --- | --- |
| `keymate doctor [service]` | Check your tools, security key and, for a service, your sign-in (`--deps-only`: tools only) |
| `keymate devices` | Show plugged-in security keys |
| `keymate setup [service]` | Add, keep, replace or restore a key |
| `keymate status [service]` | Show the keys you've set up and how each is used |
| `keymate signer [service]` | Choose which key signs commits, or turn signing off |
| `keymate nuke [service]` | Undo a setup: the service's registrations, key files and settings, and the credentials on a plugged-in key |
| `keymate update` (or `upgrade`) | Update Keymate; uses Homebrew if Homebrew installed it |

`doctor`, `devices` and `status` only read; they never ask for a PIN or touch.

Once a day, Keymate checks for a new release and mentions it after a command's
output: `→ keymate 0.2.0 is available: run keymate update`.

**Resident** keys live on the security key and can be restored on another Mac:
run `keymate setup` there and choose **Restore**. **Non-resident** keys need
their key file, so on a new Mac you set up a new key instead.

## Services

| Service | What Keymate sets up | Before you start |
| --- | --- | --- |
| GitHub | SSH access to github.com, and optionally commit and tag signing | Sign in with `gh auth login --web` |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Copyright 2026 [blturan](https://github.com/blturan). Licensed under the
[Apache License 2.0](LICENSE). Keymate is not affiliated with Yubico or any
service it supports.
