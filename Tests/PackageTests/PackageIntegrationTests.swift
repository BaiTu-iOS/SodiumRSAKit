// Created by yuxilong on 2026/11/24.
// swiftformat:options --swiftversion 5.9
import Foundation
import SodiumRSAKit
import XCTest

final class PackageIntegrationTests: XCTestCase {
    func testSwiftConsumerRoundTripAndTamperRejection() throws {
        let sender = try XCTUnwrap(NACLAsymmetricKeyPair())
        let recipient = try XCTUnwrap(NACLAsymmetricKeyPair())
        let senderPublic = sender.publicKey.data.base64EncodedString()
        let senderPrivate = sender.privateKey.data.base64EncodedString()
        let recipientPublic = recipient.publicKey.data.base64EncodedString()
        let recipientPrivate = recipient.privateKey.data.base64EncodedString()
        var nonce: NSString?
        let ciphertext = try XCTUnwrap(SodiumCrypto.encrypt(
            "SPM 中文互通",
            publicKey: recipientPublic,
            privateKey: senderPrivate,
            nonceString: &nonce
        ))
        let nonceText = try XCTUnwrap(nonce) as String
        XCTAssertEqual(
            SodiumCrypto.decrypt(
                ciphertext,
                publicKey: senderPublic,
                privateKey: recipientPrivate,
                nonceString: nonceText
            ),
            Data("SPM 中文互通".utf8)
        )
        var bytes = try XCTUnwrap(Data(base64Encoded: ciphertext, options: .ignoreUnknownCharacters))
        bytes[0] ^= 1
        XCTAssertNil(SodiumCrypto.decrypt(
            bytes.base64EncodedString(),
            publicKey: senderPublic,
            privateKey: recipientPrivate,
            nonceString: nonceText
        ))
    }

    func testRSAExportIsAvailable() {
        XCTAssertNil(BTRSATools.encryptPlainText("invalid key", publicKey: "AA=="))
    }
}
