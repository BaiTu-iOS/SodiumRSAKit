//
//  BTRSATools.m
//  SodiumRSAKit
//
//  Created by XuedanWu on 2023/5/5.
//

// Portions derived from Objective-C-RSA. Copyright (c) 2013 Objective-C-RSA Authors.
// BSD-3-Clause; see LICENSE in this directory.
#import "BTRSATools.h"

#import <Security/Security.h>

static NSString *base64EncodeData(NSData *data)
{
    // Preserve operation failure instead of turning nil data into an empty string.
    if (!data) return nil;
    data = [data base64EncodedDataWithOptions:0];
    NSString *ret = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return ret;
}

static NSData *base64Decode(NSString *str)
{
    NSData *data = [[NSData alloc] initWithBase64EncodedString:str options:NSDataBase64DecodingIgnoreUnknownCharacters];
    return data;
}

@implementation BTRSATools

#pragma mark - 使用公钥字符串加密
/* START: Encryption with RSA public key */
//使用公钥字符串加密
+ (NSString *)encryptPlainText:(NSString *)jsonStr publicKey:(NSString *)pubKey
{
    NSData *data = [self encryptData:[jsonStr dataUsingEncoding:NSUTF8StringEncoding] publicKey:pubKey];
    NSString *ret = base64EncodeData(data);
    return ret;
}

+ (NSData *)encryptJson:(NSString *)jsonStr publicKey:(NSString *)pubKey
{
    return [self encryptData:[jsonStr dataUsingEncoding:NSUTF8StringEncoding] publicKey:pubKey];
}

+ (NSData *)encryptData:(NSData *)data publicKey:(NSString *)pubKey
{
    if (!data || !pubKey) {
        return nil;
    }
    SecKeyRef keyRef = [self addPublicKey:pubKey];
    if (!keyRef) {
        return nil;
    }
    return [self encryptData:data withKeyRef:keyRef];
}

+ (SecKeyRef)addPublicKey:(NSString *)key
{

    NSRange spos = [key rangeOfString:@"-----BEGIN PUBLIC KEY-----"];
    NSRange epos = [key rangeOfString:@"-----END PUBLIC KEY-----"];
    if (spos.location != NSNotFound && epos.location != NSNotFound) {
        NSUInteger s = spos.location + spos.length;
        NSUInteger e = epos.location;
        if (e < s) return nil;
        NSRange range = NSMakeRange(s, e - s);
        key = [key substringWithRange:range];
    }
    key = [key stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\t" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@" " withString:@""];
    // This will be base64 encoded, decode it.
    NSData *data = base64Decode(key);
    data = [self stripPublicKeyHeader:data];
    if (!data) {
        return nil;
    }
    NSDictionary *attributes = @{(__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,
        (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPublic};
    CFErrorRef error = NULL;
    SecKeyRef keyRef = SecKeyCreateWithData((__bridge CFDataRef)data, (__bridge CFDictionaryRef)attributes, &error);
    if (error) CFRelease(error);
    return keyRef;
}

+ (NSData *)stripPublicKeyHeader:(NSData *)d_key
{
    // Skip ASN.1 public key header
    if (d_key == nil) return (nil);
    unsigned long len = [d_key length];
    if (len < 2) return nil;
    unsigned char *c_key = (unsigned char *)[d_key bytes];
    unsigned int idx = 0;
    if (c_key[idx++] != 0x30) return (nil);
    if (c_key[idx] > 0x80)
    idx += c_key[idx] - 0x80 + 1;
    else
    idx++;
    // PKCS #1 rsaEncryption szOID_RSA_RSA
    static unsigned char seqiod[] =
    {0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
        0x01, 0x05, 0x00};
    if (idx > len || len - idx < sizeof(seqiod) + 2) return nil;
    if (memcmp(&c_key[idx], seqiod, 15)) return (nil);
    idx += 15;
    if (c_key[idx++] != 0x03) return (nil);
    if (c_key[idx] > 0x80)
    idx += c_key[idx] - 0x80 + 1;
    else
    idx++;
    if (idx >= len) return nil;
    if (c_key[idx++] != '\0') return (nil);
    // Now make a new NSData from this buffer
    return ([NSData dataWithBytes:&c_key[idx] length:len - idx]);
}

+ (NSData *)encryptData:(NSData *)data withKeyRef:(SecKeyRef)keyRef
{
    const uint8_t *srcbuf = (const uint8_t *)[data bytes];
    size_t srclen = (size_t)data.length;
    size_t block_size = SecKeyGetBlockSize(keyRef) * sizeof(uint8_t);
    void *outbuf = malloc(block_size);
    if (!outbuf) {
        CFRelease(keyRef);
        return nil;
    }
    size_t src_block_size = block_size - 11;
    NSMutableData *ret = [[NSMutableData alloc] init];
    for (int idx = 0; idx < srclen; idx += src_block_size) {
        //NSLog(@"%d/%d block_size: %d", idx, (int)srclen, (int)block_size);
        size_t data_len = srclen - idx;
        if (data_len > src_block_size) {
            data_len = src_block_size;
        }
        size_t outlen = block_size;
        OSStatus status = noErr;
        status = SecKeyEncrypt(keyRef,
                               kSecPaddingPKCS1,
                               srcbuf + idx,
                               data_len,
                               outbuf,
                               &outlen);
        if (status != 0) {
            NSLog(@"SecKeyEncrypt fail. Error Code: %d", status);
            ret = nil;
            break;
        } else {
            [ret appendBytes:outbuf length:outlen];
        }
    }
    free(outbuf);
    CFRelease(keyRef);
    return ret;
}

/* END: Encryption with RSA public key */
#pragma mark - 使用私钥字符串解密
/* START: Decryption with RSA private key */
//使用私钥字符串解密
+ (NSString *)decryptPlainText:(NSString *)str privateKey:(NSString *)privKey
{
    if (!str) return nil;
    NSData *data = [[NSData alloc] initWithBase64EncodedString:str options:NSDataBase64DecodingIgnoreUnknownCharacters];
    data = [self decryptData:data privateKey:privKey];
    if (!data) return nil;
    NSString *ret = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return ret;
}

+ (NSData *)decryptData:(NSData *)data privateKey:(NSString *)privKey
{
    if (!data || !privKey) {
        return nil;
    }
    SecKeyRef keyRef = [self addPrivateKey:privKey];
    if (!keyRef) {
        return nil;
    }
    return [self decryptData:data withKeyRef:keyRef];
}

+ (SecKeyRef)addPrivateKey:(NSString *)key
{
    NSRange spos = [key rangeOfString:@"-----BEGIN RSA PRIVATE KEY-----"];
    NSRange epos = [key rangeOfString:@"-----END RSA PRIVATE KEY-----"];
    if (spos.location != NSNotFound && epos.location != NSNotFound) {
        NSUInteger s = spos.location + spos.length;
        NSUInteger e = epos.location;
        if (e < s) return nil;
        NSRange range = NSMakeRange(s, e - s);
        key = [key substringWithRange:range];
    }
    key = [key stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\t" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@" " withString:@""];
    // This will be base64 encoded, decode it.
    NSData *data = base64Decode(key);
    data = [self stripPrivateKeyHeader:data];
    if (!data) {
        return nil;
    }
    NSDictionary *attributes = @{(__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,
        (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPrivate};
    CFErrorRef error = NULL;
    SecKeyRef keyRef = SecKeyCreateWithData((__bridge CFDataRef)data, (__bridge CFDictionaryRef)attributes, &error);
    if (error) CFRelease(error);
    return keyRef;
}

+ (NSData *)stripPrivateKeyHeader:(NSData *)d_key
{
    // Skip ASN.1 private key header
    if (d_key == nil) return (nil);
    unsigned long len = [d_key length];
    if (len < 24) return nil;
    unsigned char *c_key = (unsigned char *)[d_key bytes];
    unsigned int idx = 22; //magic byte at offset 22
    if (0x04 != c_key[idx++]) return nil;
    //calculate length of the key
    unsigned int c_len = c_key[idx++];
    int det = c_len & 0x80;
    if (!det) {
        c_len = c_len & 0x7f;
    } else {
        int byteCount = c_len & 0x7f;
        if (byteCount == 0 || byteCount > sizeof(unsigned int) || byteCount + idx > len) {
            //rsa length field longer than buffer
            return nil;
        }
        unsigned int accum = 0;
        unsigned char *ptr = &c_key[idx];
        idx += byteCount;
        while (byteCount) {
            accum = (accum << 8) + *ptr;
            ptr++;
            byteCount--;
        }
        c_len = accum;
    }
    // Now make a new NSData from this buffer
    if (c_len > len - idx) return nil;
    return [d_key subdataWithRange:NSMakeRange(idx, c_len)];
}

+ (NSData *)decryptData:(NSData *)data withKeyRef:(SecKeyRef)keyRef
{
    const uint8_t *srcbuf = (const uint8_t *)[data bytes];
    size_t srclen = (size_t)data.length;
    size_t block_size = SecKeyGetBlockSize(keyRef) * sizeof(uint8_t);
    // RSA ciphertext must contain complete modulus-sized blocks.
    if (srclen % block_size != 0) {
        CFRelease(keyRef);
        return nil;
    }
    UInt8 *outbuf = malloc(block_size);
    if (!outbuf) {
        CFRelease(keyRef);
        return nil;
    }
    size_t src_block_size = block_size;
    NSMutableData *ret = [[NSMutableData alloc] init];
    for (int idx = 0; idx < srclen; idx += src_block_size) {
        //NSLog(@"%d/%d block_size: %d", idx, (int)srclen, (int)block_size);
        size_t data_len = srclen - idx;
        if (data_len > src_block_size) {
            data_len = src_block_size;
        }
        size_t outlen = block_size;
        OSStatus status = noErr;
        status = SecKeyDecrypt(keyRef,
                               kSecPaddingPKCS1,
                               srcbuf + idx,
                               data_len,
                               outbuf,
                               &outlen);
        if (status != 0) {
            NSLog(@"SecKeyEncrypt fail. Error Code: %d", status);
            ret = nil;
            break;
        } else {
            [ret appendBytes:outbuf length:outlen];
        }
    }
    free(outbuf);
    CFRelease(keyRef);
    return ret;
}

// 加密json, 有规则
/**
 * 有一个长度问题，请把要加密的明文切成长度 `245` ，
 * 依次对明文加密 (结果是二进制数据)
 * 拼接加密数据
 * 最后对整个二进制数据做一次 `base64` 操作
 */
+ (NSString *_Nullable)splitWithJson:(NSString *)jsonStr publicKey:(NSString *)publicKey
{
    if (jsonStr.length <= 245) {
        NSString *encryptJson = [BTRSATools encryptPlainText:jsonStr publicKey:publicKey];
        return encryptJson;
    }

    // 需要分割json串
    NSMutableData *mutJsonData = [[NSMutableData alloc] init];
    unsigned long len = jsonStr.length / 245, mod = jsonStr.length % 245;
    for (int i = 0; i < len; i++) {
        NSInteger num = 245;
        if (i == len - 1) {
            num += mod;
        }
        NSRange subRange = NSMakeRange(i * 245, num);
        NSString *newStr = [jsonStr substringWithRange:subRange];
        NSData *encryptJsonData = [BTRSATools encryptJson:newStr publicKey:publicKey];
        if (!encryptJsonData) return nil;
        [mutJsonData appendData:encryptJsonData];
    }

    /// base64 操作
    NSData *data = [mutJsonData base64EncodedDataWithOptions:0];
    NSString *ret = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (!NSStringCheckIsVaild(ret)) {
        return nil;
    }
    return ret;
}

#pragma mark - 字符串处理

/// 判断是否字符串
/// @param str 字符串
NS_INLINE BOOL NSStringCheckIsVaild(NSString *str)
{
    if (![str isKindOfClass:NSString.class]) {
        return NO;
    }
    if (str.length == 0) {
        return NO;
    }
    return YES;
}

@end
