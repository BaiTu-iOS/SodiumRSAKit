//
//  BTRSATools.h
//  SodiumRSAKit
//
//  Created by XuedanWu on 2023/5/5.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// RSA PKCS#1 v1.5 interoperability. Invalid keys or failed operations return nil.
@interface BTRSATools : NSObject

#pragma mark - 公钥私钥数据
/**
 * 加密方法 - 返回字符串
 * 加密字符串,并执行base64 操作
 */
+ (nullable NSString *)encryptPlainText:(NSString *)jsonStr publicKey:(NSString *)pubKey;

/**
 * 加密方法 - 返回NSData二进制数据
 * 加密字符串,不执行base64 操作
 */
+ (nullable NSData *)encryptJson:(NSString *)jsonStr publicKey:(NSString *)pubKey;
/**
 * 解密方法
 *
 * @param str 需要解密的字符串
 * @param privKey 私钥字符串
 */
+ (nullable NSString *)decryptPlainText:(NSString *)str privateKey:(NSString *)privKey;

// 加密json, 有规则
/**
 * 有一个长度问题，请把要加密的明文切成长度 `245` ，
 * 依次对明文加密 (结果是二进制数据)
 * 拼接加密数据
 * 最后对整个二进制数据做一次 `base64` 操作
 */
+ (NSString *_Nullable)splitWithJson:(NSString *)jsonStr publicKey:(NSString *)publicKey;

@end

NS_ASSUME_NONNULL_END
