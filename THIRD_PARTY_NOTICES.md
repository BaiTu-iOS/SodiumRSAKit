# Third-party notices

| Component | Upstream | License | Included notice |
| --- | --- | --- | --- |
| libsodium 1.0.18 minimal | https://github.com/jedisct1/libsodium/tree/1.0.18 | ISC | [License](BTCrypto/Sodium/libsodium.LICENSE) |
| NAChloride | https://github.com/gabriel/NAChloride | MIT, Gabriel Handford | [License](BTCrypto/Sodium/NAChloride/LICENSE) |
| RSA helper code | https://github.com/ideawu/Objective-C-RSA | BSD-3-Clause | [License](BTCrypto/RSATool/LICENSE) |
| SodiumObjc | https://github.com/TabbedOut/SodiumObjc | MIT, ATX Innovations | [License](BTCrypto/Sodium/SodiumObjc/LICENSE) |

The Objective-C bindings are locally modified copies. Their exact original commit revisions were not recorded in the imported source. Original file-level author notices are retained. In particular, the public-key path uses detached nonces and libsodium's easy API; it must not be assumed identical to upstream framing.

The bundled libsodium archive is rebuilt using `scripts/build-libsodium.sh`. Preserve these notices when redistributing source or binaries.

The RSA helper retains code matching Objective-C-RSA (including its key-wrapper parsing). Its upstream notice is included; local edits remove shared Keychain state and validate input bounds and padding.
