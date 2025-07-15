# Changelog

## 2.1.0

- Added a tool to test the decryption keys of privacy guardians (formerly know as anonymity recovers).
- Renamed the `anonymity_revocation` tool to `identity disclosure` and updated the user interface to reflect the new terminology. This includes the option names.
- Updated the terminology in `keygen` to use the new terminology. This includes the option names.

## 2.0.2

- Updated the internal library key_derivation to 2.0.0. This enforces that the seed phrase input must be 12, 15, 18, 21 or 24 words.

## 2.0.1

- Fixed bug where the `user_cli` tool was unable to accept the `account` flag as it conflicted with the `expiry` flag that was always set due to a default value being provided.
