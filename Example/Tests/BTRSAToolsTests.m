// Created by yuxilong on 2026/11/24.
#import <XCTest/XCTest.h>
#import <Security/Security.h>
#import <SodiumRSAKit/BTRSATools.h>

@interface BTRSAToolsTests : XCTestCase
@property(nonatomic, copy) NSData *publicDER;
@property(nonatomic, copy) NSData *privateDER;
@property(nonatomic, copy) NSString *publicKey;
@property(nonatomic, copy) NSString *privateKey;
@end

@implementation BTRSAToolsTests

- (void)setUp
{
    [super setUp];
    NSDictionary *attributes = @{(__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,
        (__bridge id)kSecAttrKeySizeInBits: @2048};
    CFErrorRef error = NULL;
    SecKeyRef privateKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attributes, &error);
    XCTAssertNotEqual(privateKey, NULL);
    if (error) CFRelease(error);
    if (!privateKey) return;
    SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
    error = NULL;
    NSData *publicDER = CFBridgingRelease(SecKeyCopyExternalRepresentation(publicKey, &error));
    XCTAssertNotNil(publicDER);
    if (error) CFRelease(error);
    error = NULL;
    NSData *privateDER = CFBridgingRelease(SecKeyCopyExternalRepresentation(privateKey, &error));
    XCTAssertNotNil(privateDER);
    if (error) CFRelease(error);
    CFRelease(publicKey);
    CFRelease(privateKey);

    // Wrap runtime-generated keys in SPKI and PKCS#8; no private key is stored in source.
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
    self.publicDER = spki;
    self.privateDER = pkcs8;
    self.publicKey = [spki base64EncodedStringWithOptions:0];
    self.privateKey = [pkcs8 base64EncodedStringWithOptions:0];
}

- (void)testRoundTripsAtBlockBoundaries
{
    for (NSNumber *length in @[@0, @1, @244, @245, @246, @490, @491, @2048]) {
        NSString *message = [@"x" stringByPaddingToLength:length.unsignedIntegerValue withString:@"x" startingAtIndex:0];
        NSString *ciphertext = [BTRSATools encryptPlainText:message publicKey:self.publicKey];
        XCTAssertNotNil(ciphertext);
        XCTAssertEqualObjects([BTRSATools decryptPlainText:ciphertext privateKey:self.privateKey], message);
        NSData *data = [[NSData alloc] initWithBase64EncodedString:ciphertext options:0];
        XCTAssertEqual(data.length, ((length.unsignedIntegerValue + 244) / 245) * 256);
    }
}

- (void)testUnicodeRoundTrip
{
    NSString *message = [@"中文🔐é" stringByPaddingToLength:600 withString:@"中文🔐é" startingAtIndex:0];
    NSString *ciphertext = [BTRSATools encryptPlainText:message publicKey:self.publicKey];
    XCTAssertEqualObjects([BTRSATools decryptPlainText:ciphertext privateKey:self.privateKey], message);
}

- (void)testRawCiphertextRoundTrip
{
    NSData *ciphertext = [BTRSATools encryptJson:@"raw bytes" publicKey:self.publicKey];
    XCTAssertEqual(ciphertext.length, 256u);
    XCTAssertEqualObjects([BTRSATools decryptPlainText:[ciphertext base64EncodedStringWithOptions:0] privateKey:self.privateKey], @"raw bytes");
}

- (void)testSplitRoundTripsMultipleBlocks
{
    for (NSNumber *length in @[@0, @245, @246, @490, @491, @1000]) {
        NSString *message = [@"x" stringByPaddingToLength:length.unsignedIntegerValue withString:@"x" startingAtIndex:0];
        NSString *ciphertext = [BTRSATools splitWithJson:message publicKey:self.publicKey];
        XCTAssertNotNil(ciphertext);
        XCTAssertEqualObjects([BTRSATools decryptPlainText:ciphertext privateKey:self.privateKey], message);
    }
}

- (void)testPEMPublicKeyAndWrappedCiphertext
{
    NSString *pem = [NSString stringWithFormat:@"-----BEGIN PUBLIC KEY-----\n%@\n-----END PUBLIC KEY-----", [self.publicDER base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength]];
    NSString *ciphertext = [BTRSATools encryptPlainText:@"PEM" publicKey:pem];
    XCTAssertNotNil(ciphertext);
    XCTAssertEqualObjects([BTRSATools decryptPlainText:[@"\r\n" stringByAppendingString:ciphertext] privateKey:self.privateKey], @"PEM");
}

- (void)testReversedPEMMarkersAreRejected
{
    NSString *pem = @"-----END PUBLIC KEY-----AA==-----BEGIN PUBLIC KEY-----";
    XCTAssertNil([BTRSATools encryptPlainText:@"sample" publicKey:pem]);
}

- (void)testMalformedKeysAreRejectedWithoutEmptySuccess
{
    for (NSString *key in @[@"", @"%%%", @"AA==", @"MAA="]) {
        XCTAssertNil([BTRSATools encryptPlainText:@"sample" publicKey:key]);
        XCTAssertNil([BTRSATools encryptJson:@"sample" publicKey:key]);
        XCTAssertNil([BTRSATools splitWithJson:[@"x" stringByPaddingToLength:600 withString:@"x" startingAtIndex:0] publicKey:key]);
        XCTAssertNil([BTRSATools decryptPlainText:@"AA==" privateKey:key]);
    }
}

- (void)testTruncatedDERKeysAreRejected
{
    for (NSNumber *length in @[@1, @2, @22, @23, @24]) {
        NSString *publicKey = [[self.publicDER subdataWithRange:NSMakeRange(0, length.unsignedIntegerValue)] base64EncodedStringWithOptions:0];
        NSString *privateKey = [[self.privateDER subdataWithRange:NSMakeRange(0, length.unsignedIntegerValue)] base64EncodedStringWithOptions:0];
        XCTAssertNil([BTRSATools encryptPlainText:@"sample" publicKey:publicKey]);
        XCTAssertNil([BTRSATools decryptPlainText:@"AA==" privateKey:privateKey]);
    }
}

- (void)testInvalidDERLengthIsRejected
{
    NSMutableData *bytes = [self.privateDER mutableCopy];
    ((uint8_t *)bytes.mutableBytes)[23] = 0x85;
    XCTAssertNil([BTRSATools decryptPlainText:@"AA==" privateKey:[bytes base64EncodedStringWithOptions:0]]);
    bytes = [self.privateDER mutableCopy];
    ((uint8_t *)bytes.mutableBytes)[24] = 0xff;
    XCTAssertNil([BTRSATools decryptPlainText:@"AA==" privateKey:[bytes base64EncodedStringWithOptions:0]]);
}

- (void)testIncompleteCiphertextBlocksAreRejected
{
    NSString *ciphertext = [BTRSATools encryptPlainText:@"sample" publicKey:self.publicKey];
    NSData *bytes = [[NSData alloc] initWithBase64EncodedString:ciphertext options:0];
    for (NSNumber *length in @[@1, @255]) {
        NSData *truncated = [bytes subdataWithRange:NSMakeRange(0, length.unsignedIntegerValue)];
        XCTAssertNil([BTRSATools decryptPlainText:[truncated base64EncodedStringWithOptions:0] privateKey:self.privateKey]);
    }
}

- (void)testInvalidPKCS1PaddingIsRejected
{
    NSString *zeroBlock = [[NSMutableData dataWithLength:256] base64EncodedStringWithOptions:0];
    XCTAssertNil([BTRSATools decryptPlainText:zeroBlock privateKey:self.privateKey]);
}

- (void)testEncryptionUsesRandomPadding
{
    NSString *first = [BTRSATools encryptPlainText:@"same" publicKey:self.publicKey];
    NSString *second = [BTRSATools encryptPlainText:@"same" publicKey:self.publicKey];
    XCTAssertNotEqualObjects(first, second);
}

@end
