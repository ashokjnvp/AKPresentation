import Foundation
import AKSecurity
import AKOpenID4VCI

/// SessionData status codes (ISO/IEC 18013-5 §9.1.1.4).
public enum AKSessionStatus: Int, Sendable {
    case encryptionError = 10
    case decodingError = 11
    case sessionTermination = 20
}

/// Holder-side ISO/IEC 18013-5 session: SessionEstablishment → DeviceRequest → DeviceResponse.
/// Transport-independent (BLE, NFC, tests).
public final class AKMDocHolderSession: @unchecked Sendable {

    public let engagement: AKDeviceEngagement
    /// Handover: null for QR, [HandoverSelect, HandoverRequest/null] for NFC.
    public let handover: AKCBOR

    public private(set) var sessionTranscript: AKCBOR?
    private var encryption: AKMDocSessionEncryption?
    private let lock = NSLock()

    public init(engagement: AKDeviceEngagement, handover: AKCBOR = .null) {
        self.engagement = engagement
        self.handover = handover
    }

    public var isEstablished: Bool { lock.lock(); defer { lock.unlock() }; return encryption != nil }

    /// Process the first message from the reader.
    public func handleSessionEstablishment(_ message: Data) throws -> AKMDocDeviceRequest {
        let cbor = try decode(message)
        guard let readerKeyBytes = cbor["eReaderKey"], let encrypted = cbor["data"]?.bytesValue else {
            throw AKPresentationError.session("SessionEstablishment must contain eReaderKey and data")
        }
        let readerKey = try akPresent { try AKCOSEKey.decodePublicKey(readerKeyBytes.decodeTag24()) }
        guard readerKey.keyType == engagement.eDeviceKey.keyType else {
            throw AKPresentationError.session("EReaderKey curve does not match EDeviceKey")
        }
        let transcript = AKSessionTranscript.proximity(deviceEngagementBytes: engagement.taggedBytes,
                                                        eReaderKeyBytes: readerKeyBytes, handover: handover)
        let session = try akPresent {
            try AKMDocSessionEncryption(role: .mdoc, privateKey: engagement.eDeviceKey, peerPublicKey: readerKey,
                                        sessionTranscriptBytes: AKSessionTranscript.bytes(transcript))
        }
        lock.lock()
        sessionTranscript = transcript
        encryption = session
        lock.unlock()
        return try decryptRequest(encrypted, session: session)
    }

    /// Process a later SessionData. Returns nil when the reader terminated the session (status 20).
    public func handleSessionData(_ message: Data) throws -> AKMDocDeviceRequest? {
        let cbor = try decode(message)
        if let status = cbor["status"]?.intValue, status == AKSessionStatus.sessionTermination.rawValue, cbor["data"] == nil {
            return nil
        }
        guard let encrypted = cbor["data"]?.bytesValue else {
            if let status = cbor["status"]?.intValue { throw AKPresentationError.session("reader reported status \(status)") }
            throw AKPresentationError.session("SessionData without data")
        }
        guard let session = currentSession() else { throw AKPresentationError.session("session not established") }
        return try decryptRequest(encrypted, session: session)
    }

    /// Dispatch any incoming message (first one is SessionEstablishment).
    public func handle(_ message: Data) throws -> AKMDocDeviceRequest? {
        if isEstablished { return try handleSessionData(message) }
        return try handleSessionEstablishment(message)
    }

    /// Encrypt a DeviceResponse into SessionData. Set `terminate` to also end the session (status 20).
    public func responseMessage(_ deviceResponse: AKCBOR, terminate: Bool = false) throws -> Data {
        guard let session = currentSession() else { throw AKPresentationError.session("session not established") }
        let ciphertext = try akPresent { try session.encrypt(deviceResponse.encoded()) }
        var m: [AKCBOR: AKCBOR] = ["data": .byteString(ciphertext)]
        if terminate { m["status"] = AKCBOR(AKSessionStatus.sessionTermination.rawValue) }
        return AKCBOR.map(m).encoded()
    }

    /// SessionData with only a status (termination or error).
    public static func statusMessage(_ status: AKSessionStatus) -> Data {
        AKCBOR.map(["status": AKCBOR(status.rawValue)]).encoded()
    }

    // MARK: Internals

    private func currentSession() -> AKMDocSessionEncryption? {
        lock.lock(); defer { lock.unlock() }
        return encryption
    }

    private func decode(_ message: Data) throws -> AKCBOR {
        do { return try AKCBOR.decode(message) } catch {
            throw AKPresentationError.session("CBOR decoding failed")
        }
    }

    private func decryptRequest(_ ciphertext: Data, session: AKMDocSessionEncryption) throws -> AKMDocDeviceRequest {
        let plaintext: Data
        do { plaintext = try session.decrypt(ciphertext) } catch {
            throw AKPresentationError.session("could not decrypt the reader's message")
        }
        let cbor = try decode(plaintext)
        return try AKMDocDeviceRequest(cbor: cbor)
    }
}
