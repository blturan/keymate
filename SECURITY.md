# Security

Keymate sets up hardware security keys, so security problems matter most here.

## Reporting a vulnerability

Please don't open a public issue. Report it privately through
[GitHub's private vulnerability reporting](https://github.com/blturan/keymate/security/advisories/new)
instead, with what you found and how to reproduce it.

## What Keymate handles

- **Private keys:** none. Keymate's keys are created on the security key and
  never leave it; the files in `~/.ssh` only hold a handle to them.
- **PIN:** typed into Keymate's prompt and handed straight to `fido2-token` or
  `ssh-keygen` (or typed into their own prompt), which unlock the key with it.
  Keymate never stores or logs it.
- **GitHub:** through the GitHub CLI's own sign-in; Keymate never sees its
  token.
- **Changes:** shown as a plan and made only after you confirm. `keymate nuke`
  undoes them.
