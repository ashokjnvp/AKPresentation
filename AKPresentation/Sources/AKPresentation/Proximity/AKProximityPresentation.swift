import Foundation
import AKSecurity
import AKOpenID4VCI

/// Events of a proximity presentation.
public enum AKProximityEvent: Sendable {
    /// Show this QR code (QR engagement).
    case engagementReady(qrCode: String)
    /// NFC engagement is active; ask the user to tap the reader.
    case nfcReady
    case waitingForReader
    case readerConnected
    /// Ask the user for consent, then call `respond` or `decline`.
    case requestReceived(AKMDocDeviceRequest, AKReaderTrust)
    case responseSent
    case finished
    case failed(String)
}

/// Which BLE role the mdoc takes.
public enum AKProximityBLEMode: Sendable {
    case peripheralServer
    case centralClient
}

/// How the device engagement is transferred.
public enum AKEngagementMethod: Sendable {
    case qrCode
    /// NFC static handover through Host Card Emulation (iOS 17.4+, entitlement required).
    case nfc
}

/// ISO/IEC 18013-5 holder: engagement (QR / NFC), BLE transport, session encryption, consent, DeviceResponse.
public final class AKProximityPresentation: @unchecked Sendable {

    public let events: AsyncStream<AKProximityEvent>
    private let continuation: AsyncStream<AKProximityEvent>.Continuation

    public let bleMode: AKProximityBLEMode
    public let engagementMethod: AKEngagementMethod
    public let readerTrustStore: AKTrustStore?

    public private(set) var engagement: AKDeviceEngagement?
    private var session: AKMDocHolderSession?
    private var transport: AKMDocTransport?
    private var transportTask: Task<Void, Never>?
    private var nfc: AnyObject?
    private var pendingRequest: AKMDocDeviceRequest?
    private let lock = NSLock()

    public init(bleMode: AKProximityBLEMode = .peripheralServer, engagementMethod: AKEngagementMethod = .qrCode,
                readerTrustStore: AKTrustStore? = nil) {
        self.bleMode = bleMode
        self.engagementMethod = engagementMethod
        self.readerTrustStore = readerTrustStore
        var c: AsyncStream<AKProximityEvent>.Continuation!
        self.events = AsyncStream { c = $0 }
        self.continuation = c
    }

    /// Start engagement and the BLE transport.
    public func start() throws {
        let options: AKBLEOptions
        switch bleMode {
        case .peripheralServer: options = AKBLEOptions(peripheralServerUUID: UUID(), centralClientUUID: nil)
        case .centralClient: options = AKBLEOptions(peripheralServerUUID: nil, centralClientUUID: UUID())
        }
        let engagement = try AKDeviceEngagement(ble: options, includeRetrievalMethods: engagementMethod == .qrCode)
        var handover: AKCBOR = .null
        var handoverSelect: Data?
        if engagementMethod == .nfc {
            let hs = AKNFCHandover.handoverSelect(engagement: engagement)
            handoverSelect = hs
            handover = AKNFCHandover.sessionHandover(handoverSelect: hs)
        }
        let session = AKMDocHolderSession(engagement: engagement, handover: handover)
        let transport: AKMDocTransport
        switch bleMode {
        case .peripheralServer: transport = AKBLEPeripheralServer(serviceUUID: options.peripheralServerUUID!)
        case .centralClient: transport = AKBLECentralClient(serviceUUID: options.centralClientUUID!, expectedIdent: engagement.bleIdent)
        }
        lock.lock()
        self.engagement = engagement
        self.session = session
        self.transport = transport
        lock.unlock()

        transportTask = Task { [weak self] in
            for await event in transport.events { self?.handle(event) }
        }
        transport.start()

        switch engagementMethod {
        case .qrCode:
            continuation.yield(.engagementReady(qrCode: engagement.qrCode))
        case .nfc:
            try startNFC(handoverSelect: handoverSelect ?? Data())
        }
    }

    private func startNFC(handoverSelect: Data) throws {
        #if canImport(CoreNFC) && os(iOS)
        if #available(iOS 17.4, *) {
            let nfc = AKNFCEngagementSession()
            self.nfc = nfc
            nfc.start(handoverSelect: handoverSelect, onRead: { [weak self] in
                self?.continuation.yield(.waitingForReader)
            }, onEnd: { [weak self] error in
                if let e = error { self?.continuation.yield(.failed("NFC: \(e.localizedDescription)")) }
            })
            continuation.yield(.nfcReady)
            return
        }
        #endif
        throw AKPresentationError.unsupported("NFC engagement requires iOS 17.4 and the HCE entitlement")
    }

    private func handle(_ event: AKTransportEvent) {
        switch event {
        case .waiting:
            continuation.yield(.waitingForReader)
        case .connected:
            continuation.yield(.readerConnected)
        case .message(let data):
            guard let session = currentSession() else { return }
            do {
                if let request = try session.handle(data) {
                    lock.lock(); pendingRequest = request; lock.unlock()
                    let trust = request.readerTrust(sessionTranscript: session.sessionTranscript ?? .null, trustStore: readerTrustStore)
                    if case .invalid(let reason) = trust {
                        send(AKMDocHolderSession.statusMessage(.sessionTermination))
                        continuation.yield(.failed("reader authentication failed: \(reason)"))
                        return
                    }
                    continuation.yield(.requestReceived(request, trust))
                } else {
                    finish()
                }
            } catch {
                // Decryption / decoding failure → status 10 / 11 and end.
                var status = AKSessionStatus.encryptionError
                if case .session(let m)? = error as? AKPresentationError, m.contains("CBOR") { status = .decodingError }
                send(AKMDocHolderSession.statusMessage(status))
                continuation.yield(.failed(error.localizedDescription))
            }
        case .disconnected:
            finish()
        case .failed(let message):
            continuation.yield(.failed(message))
        }
    }

    /// Send the approved documents.
    /// - Parameter notReturned: requested doc types the holder declined or doesn't have.
    public func respond(_ disclosures: [AKMDocDisclosure], notReturned: [String] = []) throws {
        guard let session = currentSession(), let transcript = session.sessionTranscript else {
            throw AKPresentationError.session("no active request")
        }
        let response = try AKDeviceResponseBuilder.deviceResponse(disclosures, sessionTranscript: transcript, notReturned: notReturned)
        send(try session.responseMessage(response))
        lock.lock(); pendingRequest = nil; lock.unlock()
        continuation.yield(.responseSent)
    }

    /// Decline: return no documents and end the session.
    public func decline() {
        guard let session = currentSession() else { return }
        let docTypes = pending()?.docRequests.map(\.docType) ?? []
        if let response = try? AKDeviceResponseBuilder.deviceResponse([], sessionTranscript: session.sessionTranscript ?? .null,
                                                                       notReturned: docTypes),
           let message = try? session.responseMessage(response, terminate: true) {
            send(message)
        } else {
            send(AKMDocHolderSession.statusMessage(.sessionTermination))
        }
        stop()
    }

    /// End the session (State end / status 20) and release resources.
    public func stop() {
        if let session = currentSession(), session.isEstablished {
            send(AKMDocHolderSession.statusMessage(.sessionTermination))
        }
        finish()
    }

    private func finish() {
        lock.lock()
        let t = transport
        transport = nil
        let n = nfc
        nfc = nil
        lock.unlock()
        t?.stop()
        #if canImport(CoreNFC) && os(iOS)
        if #available(iOS 17.4, *) { (n as? AKNFCEngagementSession)?.stop() }
        #else
        _ = n
        #endif
        continuation.yield(.finished)
        continuation.finish()
        transportTask?.cancel()
    }

    private func send(_ data: Data) {
        lock.lock(); let t = transport; lock.unlock()
        t?.send(data)
    }

    private func currentSession() -> AKMDocHolderSession? {
        lock.lock(); defer { lock.unlock() }
        return session
    }

    /// The request awaiting consent.
    public var currentRequest: AKMDocDeviceRequest? { pending() }
    public var sessionTranscript: AKCBOR? { currentSession()?.sessionTranscript }

    private func pending() -> AKMDocDeviceRequest? {
        lock.lock(); defer { lock.unlock() }
        return pendingRequest
    }
}
