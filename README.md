# SodiumRSAKit

面向 **iOS 15.0 及以上**的 Objective-C 加密工具库，提供基于 libsodium 的认证加密，以及用于既有协议互通的 RSA PKCS#1 v1.5 工具。支持 **Swift Package Manager** 和 **CocoaPods**。

## 安装

### Swift Package Manager

在 Xcode 的 **File → Add Package Dependencies…** 中输入：

```text
https://github.com/BaiTu-iOS/SodiumRSAKit.git
```

版本规则选择 **Up to Next Major Version：1.1.0**，添加 `SodiumRSAKit` 产品。

也可以在 `Package.swift` 中声明：

```swift
.package(url: "https://github.com/BaiTu-iOS/SodiumRSAKit.git", from: "1.1.0")
```

并给应用 target 添加：

```swift
.product(name: "SodiumRSAKit", package: "SodiumRSAKit")
```

包清单要求 Swift 5.9 / Xcode 15 或以上。SPM 提供完整库；Objective-C 可使用 `@import SodiumRSAKit;`，Swift 使用 `import SodiumRSAKit`。底层静态库随仓库提供，无需额外下载或内部访问令牌。

支持 iOS arm64 真机和 arm64/x86_64 模拟器；不支持原生 macOS、Mac Catalyst、tvOS 或 watchOS。请用 Xcode 的 iOS destination 构建和测试，不要在 Mac 上直接执行 `swift test`。

### CocoaPods

使用已发布的 Git tag：

```ruby
pod 'SodiumRSAKit', :git => 'https://github.com/BaiTu-iOS/SodiumRSAKit.git', :tag => '1.1.0'
```

本地开发：

```ruby
pod 'SodiumRSAKit', :path => '../SodiumRSAKit'
```

无需私有 Specs 源或 CocoaPods 插件。GitHub Release 和 CocoaPods trunk 是不同的发布渠道；本库目前通过 Git tag 安装，不承诺已上架 trunk。

| 子模块 | 内容 |
| --- | --- |
| `Core`（默认） | `SodiumRSAKit.h`、Sodium 与 RSA 封装 |
| `Sodium` | `SodiumCrypto` 及其运行库 |
| `RSATool` | 基于 Apple Security 的 `BTRSATools` |
| `Runtime` | libsodium 和原有 Objective-C 绑定，供已有上层封装的应用使用 |

例如只使用运行库：

```ruby
pod 'SodiumRSAKit/Runtime', :git => 'https://github.com/BaiTu-iOS/SodiumRSAKit.git', :tag => '1.1.0'
```

同一 App 不要同时链接另一份 libsodium、这些 Objective-C 绑定或旧 BTCrypto，否则可能出现重复符号。已有项目迁移时需要同时调整 Pod 依赖和模块导入；`SodiumCrypto`、`BTRSATools` 类名保持不变。

## Sodium 认证加密

以下示例在运行时生成两组临时密钥，不包含业务密钥：

```objective-c
@import SodiumRSAKit;

NACLAsymmetricKeyPair *sender = [[NACLAsymmetricKeyPair alloc] init];
NACLAsymmetricKeyPair *recipient = [[NACLAsymmetricKeyPair alloc] init];
NSString *nonce = nil;
NSString *ciphertext = [SodiumCrypto encrypt:@"你好，世界！"
                                 publicKey:[recipient.publicKey.data base64EncodedStringWithOptions:0]
                                privateKey:[sender.privateKey.data base64EncodedStringWithOptions:0]
                               nonceString:&nonce];
if (!ciphertext) {
    // 加密失败：由应用向调用方报告错误。
    return;
}
NSData *plaintext = [SodiumCrypto decrypt:ciphertext
                               publicKey:[sender.publicKey.data base64EncodedStringWithOptions:0]
                              privateKey:[recipient.privateKey.data base64EncodedStringWithOptions:0]
                             nonceString:nonce];
if (!plaintext) {
    // 认证失败：丢弃结果，不要将密文作为明文继续处理。
    return;
}
```

CocoaPods 也可以显式导入 `<SodiumRSAKit/SodiumRSAKit.h>` 和 `<SodiumRSAKit/SodiumObjc.h>`。

协议约定：

- 使用 `crypto_box_easy`：Curve25519、XSalsa20、Poly1305。
- 公钥、私钥是 **32 字节数据的 Base64**；应用负责密钥分发和安全保存。
- 每次加密生成新的 **24 字节 nonce**，通过出参独立返回；不得在相同密钥下重复使用 nonce。
- 密文是 `MAC || encrypted bytes` 的 Base64，**不包含 nonce 前缀**。
- 保留原有 Base64 每 64 字符换行行为；解密接受带换行的密文和 nonce。
- 加密传入接收方公钥、发送方私钥；解密传入发送方公钥、接收方私钥。
- 密钥或 nonce 长度错误、认证失败时返回 `nil`。不得把认证失败视为明文成功。

## RSA 协议互通

```objective-c
@import SodiumRSAKit;
// publicKey 由应用提供，是 Base64 DER SubjectPublicKeyInfo 格式的 RSA 公钥。
NSString *ciphertext = [BTRSATools encryptPlainText:@"你好" publicKey:publicKey];
```

保留以下接口：

| 方法 | 结果 |
| --- | --- |
| `encryptPlainText:publicKey:` | Base64 密文 |
| `encryptJson:publicKey:` | 原始密文字节 |
| `decryptPlainText:privateKey:` | UTF-8 明文 |
| `splitWithJson:publicKey:` | 兼容既有分段协议的 Base64 密文 |

公钥使用 Base64 DER SubjectPublicKeyInfo，也可带 `PUBLIC KEY` PEM 标记。私钥解析器沿用 **PKCS#8 包装中 OCTET STRING 位于第 22 字节**的格式约定，接受对应 DER 的 Base64；它不是通用 ASN.1/PEM 导入器，不支持直接传入裸 PKCS#1 私钥。

RSA 加密按模数大小分割 UTF-8 字节，使用 PKCS#1 v1.5 填充。`splitWithJson:` 保留原有每 245 个 UTF-16 单元的外层分段规则，新调用方优先使用 `encryptPlainText:`。密钥仅导入内存，不写入共享 Keychain。失败返回 `nil`。

RSA v1.5 仅用于已有协议互通，不提供消息认证；新协议优先采用 Sodium 认证加密接口。

## 示例与测试

### CocoaPods 示例

```sh
cd Example
pod install
open SodiumRSAKit.xcworkspace
```

运行 `SodiumRSAKit-Example` 查看解密后的示例文本。选择可用的 iOS 设备或模拟器，在 Xcode 中执行测试。

### 命令行

将 `<设备 UDID>` 替换为本机可用的 iOS Simulator UDID：

```sh
# CocoaPods：Sodium 与 RSA 行为测试，并采集覆盖率
xcodebuild test -workspace Example/SodiumRSAKit.xcworkspace \
  -scheme SodiumRSAKit-Example -destination 'platform=iOS Simulator,id=<设备 UDID>' \
  -enableCodeCoverage YES CODE_SIGNING_ALLOWED=NO

# SPM：Swift 消费端模块导入、静态库链接、往返与篡改拒绝
xcodebuild test -scheme SodiumRSAKit \
  -destination 'platform=iOS Simulator,id=<设备 UDID>' CODE_SIGNING_ALLOWED=NO
```

测试密钥全部在运行时生成。覆盖范围包含空文本/中文/长文本、与底层 C API 的密文一致性、nonce 独立性、错误密钥、篡改/截断、Base64 换行、RSA 分块边界、PEM 包装、DER 长度错误和填充错误。CI 分别执行 CocoaPods 与 SPM 测试。

本次发布验证：24 个 Objective-C 用例和 2 个 Swift 包集成用例通过。CocoaPods 测试采集的行覆盖率如下：

| 范围 | 行覆盖率 |
| --- | --- |
| `SodiumCrypto.m` | 100%（37/37） |
| `BTRSATools.m` | 88.2%（232/263） |
| 整个库（含第三方绑定） | 33.7% |

覆盖率来自本次 Xcode 测试结果，不包括未被使用的签名、对称加密等第三方 API 的完整验证。这不等同于完整密码学审计，也不代表所有第三方绑定 API 均已覆盖。

## 内置 libsodium

当前保留 **libsodium 1.0.18 minimal**，以保持与既有客户端的协议和运行库一致；这不是最新版本或无漏洞的保证。修改版本前需要同时核对头文件、静态库与协议行为。

使用 Xcode 和网络重建：

```sh
bash scripts/build-libsodium.sh
```

构建脚本会校验源码压缩包的 SHA-256。真机与模拟器 arm64 切片必须分开，不能用 `lipo` 合并不同平台的库。

## 许可证

项目采用 [MIT](LICENSE) 许可证。内置 libsodium、NAChloride、SodiumObjc 和 RSA 衍生代码保留各自许可证，详见 [第三方声明](THIRD_PARTY_NOTICES.md)。
