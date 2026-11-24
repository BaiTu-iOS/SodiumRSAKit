// Created by yuxilong on 2026/11/24.
#import <XCTest/XCTest.h>
#import <SodiumRSAKit/SodiumRSAKit.h>
#import <SodiumRSAKit/SodiumObjc.h>
#import <SodiumRSAKit/sodium.h>

@interface SodiumCryptoTests : XCTestCase
@property(nonatomic, strong) NACLAsymmetricKeyPair *sender;
@property(nonatomic, strong) NACLAsymmetricKeyPair *recipient;
@property(nonatomic, copy) NSString *senderPublic;
@property(nonatomic, copy) NSString *senderPrivate;
@property(nonatomic, copy) NSString *recipientPublic;
@property(nonatomic, copy) NSString *recipientPrivate;
@end

@implementation SodiumCryptoTests

- (void)setUp
{
    [super setUp];
    self.sender = [[NACLAsymmetricKeyPair alloc] init];
    self.recipient = [[NACLAsymmetricKeyPair alloc] init];
    self.senderPublic = [self.sender.publicKey.data base64EncodedStringWithOptions:0];
    self.senderPrivate = [self.sender.privateKey.data base64EncodedStringWithOptions:0];
    self.recipientPublic = [self.recipient.publicKey.data base64EncodedStringWithOptions:0];
    self.recipientPrivate = [self.recipient.privateKey.data base64EncodedStringWithOptions:0];
}

- (void)testRoundTripsEmptyUnicodeAndLongMessages
{
    NSArray<NSString *> *messages = @[@"", @"Hello", @"中文 🔐 café", [@"x" stringByPaddingToLength:8192 withString:@"x" startingAtIndex:0]];
    for (NSString *message in messages) {
        NSString *nonce = nil;
        NSString *ciphertext = [SodiumCrypto encrypt:message publicKey:self.recipientPublic privateKey:self.senderPrivate nonceString:&nonce];
        XCTAssertNotNil(ciphertext);
        XCTAssertEqualObjects([SodiumCrypto decrypt:ciphertext publicKey:self.senderPublic privateKey:self.recipientPrivate nonceString:nonce], [message dataUsingEncoding:NSUTF8StringEncoding]);
    }
}

- (void)testCiphertextMatchesDetachedLibsodiumFormat
{
    NSString *nonce = nil;
    NSString *message = @"独立 C API 互通";
    NSString *ciphertext = [SodiumCrypto encrypt:message publicKey:self.recipientPublic privateKey:self.senderPrivate nonceString:&nonce];
    NSData *nonceData = [[NSData alloc] initWithBase64EncodedString:nonce options:0];
    NSData *messageData = [message dataUsingEncoding:NSUTF8StringEncoding];
    NSData *cipherData = [[NSData alloc] initWithBase64EncodedString:ciphertext options:NSDataBase64DecodingIgnoreUnknownCharacters];
    NSMutableData *expected = [NSMutableData dataWithLength:messageData.length + crypto_box_MACBYTES];
    XCTAssertEqual(nonceData.length, crypto_box_NONCEBYTES);
    XCTAssertEqual(crypto_box_easy(expected.mutableBytes, messageData.bytes, messageData.length, nonceData.bytes, self.recipient.publicKey.data.bytes, self.sender.privateKey.data.bytes), 0);
    XCTAssertEqualObjects(cipherData, expected);
    XCTAssertEqualObjects([SodiumCrypto decrypt:[expected base64EncodedStringWithOptions:0] publicKey:self.senderPublic privateKey:self.recipientPrivate nonceString:nonce], messageData);
}

- (void)testNonceGenerationProducesIndependentValues
{
    NSString *first = [SodiumCrypto nonceString];
    NSString *second = [SodiumCrypto nonceString];
    XCTAssertEqual([[NSData alloc] initWithBase64EncodedString:first options:0].length, crypto_box_NONCEBYTES);
    XCTAssertNotEqualObjects(first, second);
}

- (void)testRepeatedEncryptionUsesFreshNonce
{
    NSString *firstNonce = nil;
    NSString *secondNonce = nil;
    NSString *first = [SodiumCrypto encrypt:@"same" publicKey:self.recipientPublic privateKey:self.senderPrivate nonceString:&firstNonce];
    NSString *second = [SodiumCrypto encrypt:@"same" publicKey:self.recipientPublic privateKey:self.senderPrivate nonceString:&secondNonce];
    XCTAssertNotEqualObjects(firstNonce, secondNonce);
    XCTAssertNotEqualObjects(first, second);
}

- (void)testNonceOutputMayBeNull
{
    XCTAssertNotNil([SodiumCrypto encrypt:@"sample" publicKey:self.recipientPublic privateKey:self.senderPrivate nonceString:NULL]);
}

- (void)testMalformedAndWrongLengthKeysAreRejected
{
    NSArray<NSString *> *keys = @[@"", @"%%%", @"AA==", [[NSMutableData dataWithLength:31] base64EncodedStringWithOptions:0], [[NSMutableData dataWithLength:33] base64EncodedStringWithOptions:0]];
    NSString *nonce = [SodiumCrypto nonceString];
    for (NSString *key in keys) {
        XCTAssertNil([SodiumCrypto encrypt:@"sample" publicKey:key privateKey:self.senderPrivate nonceString:NULL]);
        XCTAssertNil([SodiumCrypto encrypt:@"sample" publicKey:self.recipientPublic privateKey:key nonceString:NULL]);
        XCTAssertNil([SodiumCrypto decrypt:@"AA==" publicKey:key privateKey:self.recipientPrivate nonceString:nonce]);
        XCTAssertNil([SodiumCrypto decrypt:@"AA==" publicKey:self.senderPublic privateKey:key nonceString:nonce]);
    }
}

- (void)testMalformedNoncesAndCiphertextsAreRejected
{
    NSString *nonce = nil;
    NSString *ciphertext = [SodiumCrypto encrypt:@"sample" publicKey:self.recipientPublic privateKey:self.senderPrivate nonceString:&nonce];
    for (NSString *invalid in @[@"", @"%%%", @"AA=="]) {
        XCTAssertNil([SodiumCrypto decrypt:ciphertext publicKey:self.senderPublic privateKey:self.recipientPrivate nonceString:invalid]);
        XCTAssertNil([SodiumCrypto decrypt:invalid publicKey:self.senderPublic privateKey:self.recipientPrivate nonceString:nonce]);
    }
}

- (void)testTamperedAndTruncatedCiphertextsAreRejected
{
    NSString *nonce = nil;
    NSString *ciphertext = [SodiumCrypto encrypt:@"authenticated" publicKey:self.recipientPublic privateKey:self.senderPrivate nonceString:&nonce];
    NSMutableData *bytes = [[[NSData alloc] initWithBase64EncodedString:ciphertext options:NSDataBase64DecodingIgnoreUnknownCharacters] mutableCopy];
    ((uint8_t *)bytes.mutableBytes)[0] ^= 1;
    XCTAssertNil([SodiumCrypto decrypt:[bytes base64EncodedStringWithOptions:0] publicKey:self.senderPublic privateKey:self.recipientPrivate nonceString:nonce]);
    ((uint8_t *)bytes.mutableBytes)[0] ^= 1;
    for (NSNumber *length in @[@0, @15, @(bytes.length - 1)]) {
        NSData *truncated = [bytes subdataWithRange:NSMakeRange(0, length.unsignedIntegerValue)];
        XCTAssertNil([SodiumCrypto decrypt:[truncated base64EncodedStringWithOptions:0] publicKey:self.senderPublic privateKey:self.recipientPrivate nonceString:nonce]);
    }
}

- (void)testWrongPeerAndNonceAreRejected
{
    NSString *nonce = nil;
    NSString *ciphertext = [SodiumCrypto encrypt:@"authenticated" publicKey:self.recipientPublic privateKey:self.senderPrivate nonceString:&nonce];
    XCTAssertNil([SodiumCrypto decrypt:ciphertext publicKey:self.recipientPublic privateKey:self.recipientPrivate nonceString:nonce]);
    XCTAssertNil([SodiumCrypto decrypt:ciphertext publicKey:self.senderPublic privateKey:self.senderPrivate nonceString:nonce]);
    XCTAssertNil([SodiumCrypto decrypt:ciphertext publicKey:self.senderPublic privateKey:self.recipientPrivate nonceString:[SodiumCrypto nonceString]]);
}

- (void)testWrappedBase64IsAccepted
{
    NSString *message = [@"sample" stringByPaddingToLength:256 withString:@"sample" startingAtIndex:0];
    NSString *nonce = nil;
    NSString *ciphertext = [SodiumCrypto encrypt:message publicKey:self.recipientPublic privateKey:self.senderPrivate nonceString:&nonce];
    XCTAssertTrue([ciphertext containsString:@"\n"]);
    NSString *wrappedNonce = [@"\r\n" stringByAppendingString:nonce];
    XCTAssertEqualObjects([SodiumCrypto decrypt:ciphertext publicKey:self.senderPublic privateKey:self.recipientPrivate nonceString:wrappedNonce], [message dataUsingEncoding:NSUTF8StringEncoding]);
}

- (void)testLowOrderPeerReturnsFailure
{
    NSData *zeroKey = [NSMutableData dataWithLength:crypto_box_PUBLICKEYBYTES];
    XCTAssertNil([SodiumCrypto encrypt:@"sample" publicKey:[zeroKey base64EncodedStringWithOptions:0] privateKey:self.senderPrivate nonceString:NULL]);
    NACLAsymmetricPublicKey *peer = [[NACLAsymmetricPublicKey alloc] initWithData:zeroKey];
    NSError *error = nil;
    NSData *result = [[@"sample" dataUsingEncoding:NSUTF8StringEncoding] encryptedDataUsingPublicKey:peer privateKey:self.sender.privateKey nonce:[NACLNonce nonce] error:&error];
    XCTAssertNil(result);
    XCTAssertNotNil(error);
}

- (void)testRuntimeReportsInvalidKeyAndMissingNonce
{
    NSData *message = [@"sample" dataUsingEncoding:NSUTF8StringEncoding];
    NACLAsymmetricPublicKey *shortKey = [[NACLAsymmetricPublicKey alloc] initWithData:[NSData data]];
    NSError *error = nil;
    XCTAssertNil([message encryptedDataUsingPublicKey:shortKey privateKey:self.sender.privateKey nonce:[NACLNonce nonce] error:&error]);
    XCTAssertNotNil(error);
    error = nil;
    XCTAssertNil([message decryptedDataUsingPublicKey:self.sender.publicKey privateKey:self.recipient.privateKey nonce:NULL error:&error]);
    XCTAssertNotNil(error);
}

@end
