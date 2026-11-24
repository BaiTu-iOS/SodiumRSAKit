//
//  SodiumCrypto.m
//  BTCrypto
//
//  Created by yuxilong on 2022/7/12.
//

#import "SodiumCrypto.h"

#import "SodiumObjc.h"
#import "sodium.h"
#import "NAChloride.h"

@implementation SodiumCrypto

+ (NACLNonce *)nonce
{
    NSData *nonceData = [NARandom randomData:NABoxNonceSize];
    return [NACLNonce nonceWithData:nonceData];
}

+ (NSString *)nonceString
{
    NSData *data = [self nonce].data;
    return [data base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
}

/// 加密
/// @param textContent 文本内容
/// @param publicKey Base64格式公钥
/// @param privateKey Base64格式私钥
+ (NSString *)encrypt:(NSString *)textContent publicKey:(NSString *)publicKey privateKey:(NSString *)privateKey nonceString:(NSString *_Nullable __autoreleasing *)nonceString
{
    NSData *privateKeyData = [[NSData alloc] initWithBase64EncodedString:privateKey options:0];
    if (privateKeyData.length != crypto_box_SECRETKEYBYTES) return nil;
    NACLAsymmetricPrivateKey *privateKeyObject = [[NACLAsymmetricPrivateKey alloc] initWithData:privateKeyData];

    NSData *publicKeyData = [[NSData alloc] initWithBase64EncodedString:publicKey options:0];
    if (publicKeyData.length != crypto_box_PUBLICKEYBYTES) return nil;
    NACLAsymmetricPublicKey *publicKeyObject = [[NACLAsymmetricPublicKey alloc] initWithData:publicKeyData];

    // 加密
    NACLNonce *nonce = [self nonce];
    if (nonceString) *nonceString = [nonce.data base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    NSData *encryptData = [textContent encryptedDataUsingPublicKey:publicKeyObject
                                                        privateKey:privateKeyObject
                                                             nonce:nonce];

    // 加密结果进行Base64
    NSString *content = [encryptData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    return content;
}

/// 解密
/// @param textContent 待解密数据
/// @param publicKey Base64格式公钥
/// @param privateKey Base64格式私钥
/// @param nonceString Base64格式随机串
+ (NSData *)decrypt:(NSString *)textContent publicKey:(NSString *)publicKey privateKey:(NSString *)privateKey nonceString:(NSString *)nonceString
{
    NSData *privateKeyData = [[NSData alloc] initWithBase64EncodedString:privateKey options:0];
    if (privateKeyData.length != crypto_box_SECRETKEYBYTES) return nil;
    NACLAsymmetricPrivateKey *privateKeyObject = [[NACLAsymmetricPrivateKey alloc] initWithData:privateKeyData];

    NSData *publicKeyData = [[NSData alloc] initWithBase64EncodedString:publicKey options:0];
    if (publicKeyData.length != crypto_box_PUBLICKEYBYTES) return nil;
    NACLAsymmetricPublicKey *publicKeyObject = [[NACLAsymmetricPublicKey alloc] initWithData:publicKeyData];

    NSData *nonceData = [[NSData alloc] initWithBase64EncodedString:nonceString options:NSDataBase64DecodingIgnoreUnknownCharacters];
    if (nonceData.length != crypto_box_NONCEBYTES) return nil;
    NACLNonce *nonce = [NACLNonce nonceWithData:nonceData];

    // 解密
    NSData *data = [[NSData alloc] initWithBase64EncodedString:textContent options:NSDataBase64DecodingIgnoreUnknownCharacters];
    data = [data decryptedDataUsingPublicKey:publicKeyObject privateKey:privateKeyObject nonce:&nonce];
    return data;
}

@end
