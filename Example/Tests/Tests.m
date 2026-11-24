// Created by yuxilong on 2026/11/24.
#import <XCTest/XCTest.h>
#import <Security/Security.h>
#import <SodiumRSAKit/SodiumRSAKit.h>
#import <SodiumRSAKit/SodiumObjc.h>
#import <SodiumRSAKit/sodium.h>

@interface Tests : XCTestCase
@end

@implementation Tests

- (void)testPublicEncryptionCompatibility
{
    NACLAsymmetricKeyPair *sender = [[NACLAsymmetricKeyPair alloc] init];
    NACLAsymmetricKeyPair *recipient = [[NACLAsymmetricKeyPair alloc] init];
    NSString *senderPublic = [sender.publicKey.data base64EncodedStringWithOptions:0];
    NSString *senderPrivate = [sender.privateKey.data base64EncodedStringWithOptions:0];
    NSString *recipientPublic = [recipient.publicKey.data base64EncodedStringWithOptions:0];
    NSString *recipientPrivate = [recipient.privateKey.data base64EncodedStringWithOptions:0];
    NSString *message = [@"Hello, 世界! " stringByPaddingToLength:600 withString:@"sample" startingAtIndex:0];
    NSData *messageData = [message dataUsingEncoding:NSUTF8StringEncoding];
    NSString *nonce = nil;
    NSString *ciphertext = [SodiumCrypto encrypt:message publicKey:recipientPublic privateKey:senderPrivate nonceString:&nonce];
    XCTAssertNotNil(ciphertext);
    XCTAssertEqualObjects([SodiumCrypto decrypt:ciphertext publicKey:senderPublic privateKey:recipientPrivate nonceString:nonce], messageData);

    // Verify detached MAC+ciphertext framing independently of the Objective-C wrappers.
    NSData *nonceData = [[NSData alloc] initWithBase64EncodedString:nonce options:0];
    NSData *cipherData = [[NSData alloc] initWithBase64EncodedString:ciphertext options:NSDataBase64DecodingIgnoreUnknownCharacters];
    NSMutableData *expected = [NSMutableData dataWithLength:messageData.length + crypto_box_MACBYTES];
    XCTAssertEqual(crypto_box_easy(expected.mutableBytes, messageData.bytes, messageData.length,
                                   nonceData.bytes, recipient.publicKey.data.bytes, sender.privateKey.data.bytes),
                   0);
    XCTAssertEqualObjects(cipherData, expected);
    ((uint8_t *)expected.mutableBytes)[0] ^= 1;
    XCTAssertNil([SodiumCrypto decrypt:[expected base64EncodedStringWithOptions:0] publicKey:senderPublic privateKey:recipientPrivate nonceString:nonce]);
    XCTAssertNil([SodiumCrypto encrypt:message publicKey:@"AA==" privateKey:senderPrivate nonceString:&nonce]);
    XCTAssertNil([SodiumCrypto decrypt:ciphertext publicKey:senderPublic privateKey:recipientPrivate nonceString:@"AA=="]);
    XCTAssertNotNil([SodiumCrypto encrypt:message publicKey:recipientPublic privateKey:senderPrivate nonceString:NULL]);

    NACLAsymmetricPublicKey *invalidPeer = [[NACLAsymmetricPublicKey alloc] initWithData:[NSMutableData dataWithLength:crypto_box_PUBLICKEYBYTES]];
    NSError *encryptionError = nil;
    NSData *failed = [messageData encryptedDataUsingPublicKey:invalidPeer privateKey:sender.privateKey
                                                        nonce:[NACLNonce nonceWithData:nonceData]
                                                        error:&encryptionError];
    XCTAssertNil(failed);
    XCTAssertNotNil(encryptionError);

    // Generate ephemeral RSA material; only DER structure constants are checked in.
    NSDictionary *attributes = @{(__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,
                                 (__bridge id)kSecAttrKeySizeInBits: @2048};
    CFErrorRef keyError = NULL;
    SecKeyRef privateKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attributes, &keyError);
    XCTAssertNotEqual(privateKey, NULL);
    if (keyError) CFRelease(keyError);
    if (!privateKey) return;
    SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
    CFErrorRef exportError = NULL;
    NSData *publicDER = CFBridgingRelease(SecKeyCopyExternalRepresentation(publicKey, &exportError));
    XCTAssertNotNil(publicDER);
    if (exportError) CFRelease(exportError);
    exportError = NULL;
    NSData *privateDER = CFBridgingRelease(SecKeyCopyExternalRepresentation(privateKey, &exportError));
    XCTAssertNotNil(privateDER);
    if (exportError) CFRelease(exportError);
    CFRelease(publicKey);
    CFRelease(privateKey);

    NSUInteger publicSize = publicDER.length;
    uint8_t publicHeader[] = {0x30, 0x82, (publicSize + 20) >> 8, (publicSize + 20) & 255,
                              0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
                              0x03, 0x82, (publicSize + 1) >> 8, (publicSize + 1) & 255, 0x00};
    NSMutableData *spki = [NSMutableData dataWithBytes:publicHeader length:sizeof(publicHeader)];
    [spki appendData:publicDER];
    NSUInteger privateSize = privateDER.length;
    uint8_t privateHeader[] = {0x30, 0x82, (privateSize + 22) >> 8, (privateSize + 22) & 255, 0x02, 0x01, 0x00,
                               0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
                               0x04, 0x82, privateSize >> 8, privateSize & 255};
    NSMutableData *pkcs8 = [NSMutableData dataWithBytes:privateHeader length:sizeof(privateHeader)];
    [pkcs8 appendData:privateDER];
    NSString *rsaPublic = [spki base64EncodedStringWithOptions:0];
    NSString *rsaPrivate = [pkcs8 base64EncodedStringWithOptions:0];
    NSString *rsaCiphertext = [BTRSATools splitWithJson:message publicKey:rsaPublic];
    XCTAssertNotNil(rsaCiphertext);
    XCTAssertEqualObjects([BTRSATools decryptPlainText:rsaCiphertext privateKey:rsaPrivate], message);
    XCTAssertNil([BTRSATools encryptPlainText:message publicKey:@"AA=="]);
    XCTAssertNil([BTRSATools decryptPlainText:@"AA==" privateKey:@"AA=="]);
}

@end
