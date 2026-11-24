//
//  SodiumCrypto.h
//  BTCrypto
//
//  Created by yuxilong on 2022/7/12.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Authenticated encryption with detached nonces. Invalid inputs or authentication failure return nil.
@interface SodiumCrypto : NSObject

/// 加密随机串 Base64格式
+ (NSString *)nonceString;

/// 加密
/// @param textContent 文本内容
/// @param publicKey Base64格式公钥
/// @param privateKey Base64格式私钥
/// @param nonceString Base64格式随机串
+ (nullable NSString *)encrypt:(NSString *)textContent publicKey:(NSString *)publicKey privateKey:(NSString *)privateKey nonceString:(NSString *_Nullable *_Nullable)nonceString;

/// 解密
/// @param textContent 待解密数据
/// @param publicKey Base64格式公钥
/// @param privateKey Base64格式私钥
/// @param nonceString Base64格式随机串
+ (nullable NSData *)decrypt:(NSString *)textContent publicKey:(NSString *)publicKey privateKey:(NSString *)privateKey nonceString:(NSString *)nonceString;

@end

NS_ASSUME_NONNULL_END
