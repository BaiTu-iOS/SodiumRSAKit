# SodiumRSAKit

Objective-C encryption utilities for iOS 15 and later. Includes authenticated public-key encryption backed by libsodium and RSA PKCS#1 v1.5 interoperability helpers.

## Installation

The public release starts at **1.0.0**. Use a local checkout during development:

```ruby
pod 'SodiumRSAKit', :path => '../SodiumRSAKit'
```

The public repository can be used directly before the first tagged release:

```ruby
pod 'SodiumRSAKit', :git => 'https://github.com/BaiTu-iOS/SodiumRSAKit.git', :branch => 'main'
```

After the `1.0.0` tag is published:

```ruby
pod 'SodiumRSAKit', :git => 'https://github.com/BaiTu-iOS/SodiumRSAKit.git', :tag => '1.0.0'
```

No private spec repository, plugin, access token, or binary-mode environment variable is required. This repository does not claim availability on CocoaPods trunk.

| Subspec | Contents |
| --- | --- |
| `Core` (default) | `SodiumRSAKit.h`, Sodium and RSA wrappers |
| `Sodium` | `SodiumCrypto` and its runtime |
| `RSATool` | `BTRSATools`, using Apple's Security framework |
| `Runtime` | libsodium and existing Objective-C bindings for applications with their own wrappers |

`Runtime` exposes `SodiumObjc.h`, `NAChloride.h`, and `sodium.h` through the `SodiumRSAKit` module. Select it with `pod 'SodiumRSAKit/Runtime', :path => '../SodiumRSAKit'`. Do not link another copy of libsodium or these Objective-C classes into the same application. The bindings include inherited APIs beyond the public-key path exercised by the example; they have not received a complete security audit.

## Authenticated encryption

```objective-c
#import <SodiumRSAKit/SodiumRSAKit.h>
#import <SodiumRSAKit/SodiumObjc.h>

NACLAsymmetricKeyPair *sender = [[NACLAsymmetricKeyPair alloc] init];
NACLAsymmetricKeyPair *recipient = [[NACLAsymmetricKeyPair alloc] init];
NSString *nonce = nil;
NSString *ciphertext = [SodiumCrypto encrypt:@"Hello, world!"
                                 publicKey:[recipient.publicKey.data base64EncodedStringWithOptions:0]
                                privateKey:[sender.privateKey.data base64EncodedStringWithOptions:0]
                               nonceString:&nonce];
NSData *plaintext = [SodiumCrypto decrypt:ciphertext
                               publicKey:[sender.publicKey.data base64EncodedStringWithOptions:0]
                              privateKey:[recipient.privateKey.data base64EncodedStringWithOptions:0]
                             nonceString:nonce];
```

The example generates temporary keys. Applications own key distribution and storage; private keys must not be committed or logged.

- Algorithm: libsodium `crypto_box_easy` (Curve25519, XSalsa20, Poly1305).
- Public/private keys: Base64-encoded 32-byte values.
- Nonce: a fresh random 24-byte value for each encryption, returned separately as Base64.
- Ciphertext: Base64 of `MAC || encrypted bytes`; the nonce is **not** prepended.
- Existing 64-character Base64 line wrapping is preserved. Decoding accepts wrapped ciphertext and nonces.
- Encryption uses the recipient's public key and sender's private key; decryption uses the sender's public key and recipient's private key.
- Invalid key/nonce lengths or authentication failures return `nil`. Callers must handle failure explicitly; never treat failed authentication as plaintext.

## RSA interoperability

```objective-c
#import <SodiumRSAKit/BTRSATools.h>
// publicKey is a Base64 DER SubjectPublicKeyInfo RSA key supplied by your application.
NSString *ciphertext = [BTRSATools encryptPlainText:@"Hello, world!" publicKey:publicKey];
```

Existing selectors (`encryptPlainText:publicKey:`, `encryptJson:publicKey:`, `decryptPlainText:privateKey:`, and `splitWithJson:publicKey:`) are retained. Public keys use Base64 DER SubjectPublicKeyInfo, optionally enclosed in `PUBLIC KEY` PEM markers. The inherited private-key parser expects the PKCS#8 wrapper layout with the OCTET STRING at byte 22; it is not a general-purpose PEM/ASN.1 importer. Bare PKCS#1 private keys are not supported by this parser.

Encryption uses PKCS#1 v1.5 padding and splits UTF-8 bytes according to the RSA modulus size. `splitWithJson:` retains its existing 245-UTF-16-unit outer chunking for interoperability; prefer `encryptPlainText:` for new callers. RSA keys are imported into memory without shared Keychain entries. Failures return `nil`.

RSA v1.5 is provided for existing protocols, not as a new authenticated messaging protocol. Use the authenticated Sodium interface for new protocols.

## Example and verification

```sh
cd Example
pod install
open SodiumRSAKit.xcworkspace
```

Run `SodiumRSAKit-Example` to see the decrypted sample text. The `SodiumRSAKit_Tests` target contains one interoperability regression covering detached Sodium framing, tamper rejection, malformed inputs, and RSA round trips with temporary keys. Select a supported destination in Xcode before running tests.

## Bundled native library

The repository includes libsodium **1.0.18 minimal**, with iOS arm64 and iOS Simulator arm64/x86_64 slices. It does not include a native macOS slice. Version 1.0.18 is retained for interoperability with the original consumers; this is not a claim that it is the latest release or free of vulnerabilities.

Rebuild with Xcode and network access:

```sh
bash scripts/build-libsodium.sh
```

The script verifies the source archive SHA-256 before building. Platform slices stay separate; do not combine device and simulator arm64 archives with `lipo`.

## License

SodiumRSAKit is distributed under the [MIT license](LICENSE). Bundled dependencies retain their own notices; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
