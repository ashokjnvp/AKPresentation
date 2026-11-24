import XCTest
import AKSecurity
import AKOpenID4VCI
@testable import AKPresentation

/// An ISO/IEC 18013-5 mdoc reader simulated with AKSecurity primitives.
struct SimulatedReader {
    let key: AKPrivateKey
    let eReaderKeyBytes: AKCBOR
    let transcript: AKCBOR
    let session: AKMDocSessionEncryption

    init(engagementBytes: Data, eDeviceKey: AKPublicKey, handover: AKCBOR = .null) throws {
        key = try AKPrivateKey.generate(.ec(.p256))
        eReaderKeyBytes = AKCBOR.encodedCBOR(try AKCOSEKey.encode(key.publicKey))
        transcript = .array([.tagged(24, .byteString(engagementBytes)), eReaderKeyBytes, handover])
        session = try AKMDocSessionEncryption(role: .reader, privateKey: key, peerPublicKey: eDeviceKey,
                                              sessionTranscriptBytes: AKSessionTranscript.bytes(transcript))
    }

    func deviceRequest(signed: Bool) throws -> AKCBOR {
        let items: AKCBOR = ["docType": "org.iso.18013.5.1.mDL",
                             "nameSpaces": ["org.iso.18013.5.1": ["given_name": true, "age_over_18": false]]]
        let itemsBytes = AKCBOR.encodedCBOR(items)
        var docRequest: [AKCBOR: AKCBOR] = ["itemsRequest": itemsBytes]
        if signed {
            let readerKey = try AKPrivateKey(pem: TestPKI.readerKey)
            let readerCert = try AKCertificate(pem: TestPKI.readerCert)
            let payload = AKCBOR.encodedCBOR(.array(["ReaderAuthentication", transcript, itemsBytes])).encoded()
            let auth = try AKCOSESign1.sign(payload: payload, key: readerKey, algorithm: .es256,
                                            unprotectedHeader: [AKCOSEHeader.x5chain: .byteString(readerCert.der)], detached: true)
            docRequest["readerAuth"] = auth.cbor
        }
        return ["version": "1.0", "docRequests": [.map(docRequest)]]
    }

    func establishment(_ request: AKCBOR) throws -> Data {
        let encrypted = try session.encrypt(request.encoded())
        return AKCBOR.map(["eReaderKey": eReaderKeyBytes, "data": .byteString(encrypted)]).encoded()
    }

    func decrypt(_ sessionData: Data) throws -> AKCBOR {
        let cbor = try AKCBOR.decode(sessionData)
        return try AKCBOR.decode(session.decrypt(try XCTUnwrap(cbor["data"]?.bytesValue)))
    }
}

final class AKProximityTests: XCTestCase {

    func testDeviceEngagementQRCode() throws {
        let uuid = UUID()
        let engagement = try AKDeviceEngagement(ble: AKBLEOptions(peripheralServerUUID: uuid, centralClientUUID: nil))
        XCTAssertTrue(engagement.qrCode.hasPrefix("mdoc:"))
        let parsed = try AKDeviceEngagement.parse(qrCode: engagement.qrCode)
        XCTAssertEqual(parsed.cbor[0], "1.0")
        XCTAssertEqual(parsed.eDeviceKey, engagement.eDeviceKey.publicKey)
        XCTAssertEqual(parsed.ble.peripheralServerUUID, uuid)
        XCTAssertNil(parsed.ble.centralClientUUID)
        XCTAssertEqual(engagement.bleIdent.count, 16)
        XCTAssertThrowsError(try AKDeviceEngagement.parse(qrCode: "https://example.com"))
        // NFC engagement omits DeviceRetrievalMethods.
        XCTAssertNil(try AKDeviceEngagement(includeRetrievalMethods: false).cbor[2])
    }

    func testHolderSessionWithReaderAuthentication() throws {
        let holder = try AKSoftwareJWTSigner.generate()
        let mdoc = try AKMDocCredential(base64URL: TestCredentials.mdoc(holder: holder))
        let engagement = try AKDeviceEngagement()
        let session = AKMDocHolderSession(engagement: engagement)
        let reader = try SimulatedReader(engagementBytes: engagement.bytes, eDeviceKey: engagement.eDeviceKey.publicKey)

        let request = try XCTUnwrap(try session.handle(reader.establishment(reader.deviceRequest(signed: true))))
        XCTAssertEqual(request.docRequests.first?.docType, "org.iso.18013.5.1.mDL")
        XCTAssertEqual(request.docRequests.first?.nameSpaces["org.iso.18013.5.1"], ["given_name": true, "age_over_18": false])
        XCTAssertEqual(session.sessionTranscript, reader.transcript)

        let readerCA = AKTrustStore(anchors: [try AKCertificate(pem: TestPKI.readerRoot)])
        XCTAssertEqual(request.readerTrust(sessionTranscript: reader.transcript, trustStore: readerCA), .trusted(commonName: "Test Reader"))
        XCTAssertEqual(request.readerTrust(sessionTranscript: reader.transcript, trustStore: nil), .untrusted(commonName: "Test Reader"))
        if case .invalid = request.readerTrust(sessionTranscript: .null, trustStore: readerCA) {} else {
            XCTFail("readerAuth over a different transcript must be invalid")
        }

        // Holder answers with the approved elements.
        let disclosure = AKMDocDisclosure(credential: mdoc, docType: "org.iso.18013.5.1.mDL",
                                          elements: ["org.iso.18013.5.1": ["given_name", "age_over_18"]], signer: holder)
        let response = try AKDeviceResponseBuilder.deviceResponse([disclosure], sessionTranscript: try XCTUnwrap(session.sessionTranscript))
        let message = try session.responseMessage(response)

        // Reader decrypts and verifies.
        let deviceResponse = try reader.decrypt(message)
        let doc = try XCTUnwrap(deviceResponse["documents"]?.arrayValue?.first)
        let issuerAuth = try AKCOSESign1(cbor: XCTUnwrap(doc["issuerSigned"]?["issuerAuth"]))
        let mso = try AKMDocVerifier.verifyIssuerAuth(issuerAuth, trustStore: AKTrustStore(anchors: [try AKCertificate(pem: TestPKI.iaca)])).mso
        let authBytes = AKMDocVerifier.deviceAuthenticationBytes(sessionTranscript: reader.transcript, docType: "org.iso.18013.5.1.mDL",
                                                                  deviceNameSpacesBytes: try XCTUnwrap(doc["deviceSigned"]?["nameSpaces"]))
        let sig = try AKCOSESign1(cbor: XCTUnwrap(doc["deviceSigned"]?["deviceAuth"]?["deviceSignature"]))
        XCTAssertNoThrow(try AKMDocVerifier.verifyDeviceSignature(sig, mso: mso, deviceAuthenticationBytes: authBytes))
        XCTAssertEqual(doc["issuerSigned"]?["nameSpaces"]?["org.iso.18013.5.1"]?.arrayValue?.count, 2)

        // Reader terminates.
        XCTAssertNil(try session.handle(AKMDocHolderSession.statusMessage(.sessionTermination)))
    }

    func testHolderSessionRejectsGarbage() throws {
        let session = AKMDocHolderSession(engagement: try AKDeviceEngagement())
        XCTAssertThrowsError(try session.handle(Data([0xff, 0x00])))
        let other = try AKDeviceEngagement()
        let reader = try SimulatedReader(engagementBytes: other.bytes, eDeviceKey: other.eDeviceKey.publicKey)
        // Encrypted for a different engagement → decryption fails.
        XCTAssertThrowsError(try session.handle(reader.establishment(reader.deviceRequest(signed: false))))
    }

    func testNFCStaticHandoverAndType4Tag() throws {
        let engagement = try AKDeviceEngagement(ble: AKBLEOptions(peripheralServerUUID: UUID(), centralClientUUID: nil),
                                                includeRetrievalMethods: false)
        let hs = AKNFCHandover.handoverSelect(engagement: engagement)
        let records = try AKNDEFRecord.parse(hs)
        XCTAssertEqual(records.map { String(decoding: $0.type, as: UTF8.self) },
                       ["Hs", "application/vnd.bluetooth.le.oob", "iso.org:18013:deviceengagement"])
        XCTAssertEqual(records[2].payload, engagement.bytes)
        XCTAssertEqual(String(decoding: records[2].id, as: UTF8.self), "mdoc")
        let oob = [UInt8](records[1].payload)
        XCTAssertEqual(Array(oob[0..<3]), [0x02, 0x1C, 0x00])
        XCTAssertEqual(Array(oob[3..<5]), [0x11, 0x07])

        // Read the NDEF file like a reader would.
        let tag = AKType4TagEmulator(ndefMessage: hs)
        XCTAssertEqual(tag.process(Data([0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00])), Data([0x90, 0x00]))
        XCTAssertEqual(tag.process(Data([0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x03])), Data([0x90, 0x00]))
        let cc = tag.process(Data([0x00, 0xB0, 0x00, 0x00, 0x0F]))
        XCTAssertEqual(cc.count, 17)
        XCTAssertEqual(Array(cc.suffix(2)), [0x90, 0x00])
        XCTAssertEqual(tag.process(Data([0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x04])), Data([0x90, 0x00]))
        let lengthResponse = [UInt8](tag.process(Data([0x00, 0xB0, 0x00, 0x00, 0x02])))
        let length = Int(lengthResponse[0]) << 8 | Int(lengthResponse[1])
        XCTAssertEqual(length, hs.count)
        var ndef = Data()
        var offset = 2
        while offset < length + 2 {
            let r = tag.process(Data([0x00, 0xB0, UInt8(offset >> 8), UInt8(offset & 0xFF), 0x80]))
            XCTAssertEqual(Array(r.suffix(2)), [0x90, 0x00])
            ndef.append(r.dropLast(2))
            offset += r.count - 2
        }
        XCTAssertEqual(ndef, hs)
        XCTAssertEqual(tag.process(Data([0x00, 0xA4, 0x04, 0x00, 0x02, 0xA0, 0x00])), Data([0x6A, 0x82]))
        XCTAssertEqual(tag.process(Data([0x00, 0xCA, 0x00, 0x00])), Data([0x6D, 0x00]))

        // Session over NFC handover.
        let handover = AKNFCHandover.sessionHandover(handoverSelect: hs)
        let session = AKMDocHolderSession(engagement: engagement, handover: handover)
        let reader = try SimulatedReader(engagementBytes: records[2].payload, eDeviceKey: engagement.eDeviceKey.publicKey, handover: handover)
        XCTAssertNotNil(try session.handle(reader.establishment(reader.deviceRequest(signed: false))))
        XCTAssertEqual(session.sessionTranscript, reader.transcript)
    }

    func testBLEFraming() throws {
        let message = Data((0..<1000).map { UInt8($0 % 251) })
        let chunks = AKBLEFraming.chunks(message, chunkSize: 185)
        XCTAssertTrue(chunks.allSatisfy { $0.count <= 185 })
        XCTAssertEqual(chunks.last?.first, 0x00)
        XCTAssertTrue(chunks.dropLast().allSatisfy { $0.first == 0x01 })
        let reassembler = AKBLEFraming.Reassembler()
        var result: Data?
        for c in chunks { result = try reassembler.append(c) ?? result }
        XCTAssertEqual(result, message)
        XCTAssertEqual(AKBLEFraming.chunks(Data(), chunkSize: 20), [Data([0x00])])
        XCTAssertThrowsError(try AKBLEFraming.Reassembler().append(Data([0x07, 0x01])))
    }

    func testDeclineResponseStructure() throws {
        let response = try AKDeviceResponseBuilder.deviceResponse([], sessionTranscript: .null, notReturned: ["org.iso.18013.5.1.mDL"])
        XCTAssertNil(response["documents"])
        XCTAssertEqual(response["documentErrors"]?.arrayValue?.first?["org.iso.18013.5.1.mDL"], 0)
        XCTAssertEqual(AKDeviceResponseBuilder.errorResponse(status: 10)["status"], 10)
    }
}
