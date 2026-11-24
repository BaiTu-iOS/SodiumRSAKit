# 更新日志

## 1.1.0

- 新增 Swift Package Manager 产品，复用既有 libsodium XCFramework 和 Objective-C 实现。
- 将单一回归拆分为 Sodium / RSA 行为测试，补充异常输入、篡改、分块、DER 与 PEM 覆盖。
- 新增 Swift 包消费端集成测试，验证模块导入、链接和认证加密行为。
- CI 从仅构建测试目标改为分别运行 CocoaPods 与 SPM 测试。
- README 默认使用简体中文，补充稳定版本安装方法、协议约定和支持范围。

## 初始公开代码（未打版本 tag）

- 提供 Core、Sodium、RSATool、Runtime CocoaPods 子模块。
- 脱敏示例、移除内部配置并补齐第三方许可证。
- 保留公开接口与独立 nonce 的密文格式，修正输入边界与失败返回值。
