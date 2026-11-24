# Changelog

## 1.0.0 — unreleased

- Prepare a standalone public CocoaPods library with Core, Sodium, RSATool, and Runtime subspecs.
- Retain public wrapper selectors and the existing detached-nonce encryption format.
- Replace embedded example credentials with runtime-generated keys and generic content.
- Include dependency licenses and a reproducible libsodium build script.
- Reject malformed public-key inputs and return nil on encryption failure.
- Import RSA keys without shared Keychain state and validate PKCS#1 padding on decryption.
