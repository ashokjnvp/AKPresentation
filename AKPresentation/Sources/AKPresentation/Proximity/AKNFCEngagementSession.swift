import Foundation

#if canImport(CoreNFC) && os(iOS)
import CoreNFC

/// NFC device engagement via Host Card Emulation (CardSession, iOS 17.4+).
///
/// Requires the `com.apple.developer.nfc.hce` entitlement and
/// `com.apple.developer.nfc.hce.iso7816.select-identifier-prefixes` = ["D2760000850101"].
/// Apple grants these entitlements per app (EEA only at the time of writing).
@available(iOS 17.4, *)
public final class AKNFCEngagementSession: @unchecked Sendable {

    private var task: Task<Void, Never>?
    private var cardSession: CardSession?
    private var presentmentIntent: NFCPresentmentIntentAssertion?

    public init() {}

    /// Device and region support. Also gate on your own feature flag: without the HCE entitlement,
    /// creating a CardSession traps.
    public static func isAvailable() async -> Bool {
        guard NFCReaderSession.readingAvailable, CardSession.isSupported else { return false }
        return await CardSession.isEligible
    }

    /// Serve the Handover Select NDEF message until the reader has read it (or the session ends).
    /// - Parameter onRead: called once the reader read the complete NDEF file.
    public func start(handoverSelect: Data, alertMessage: String = "Hold near the reader",
                      onRead: @escaping @Sendable () -> Void,
                      onEnd: @escaping @Sendable (Error?) -> Void) {
        let emulator = AKType4TagEmulator(ndefMessage: handoverSelect)
        let ndefLength = handoverSelect.count + 2
        task = Task { [weak self] in
            do {
                let intent = try await NFCPresentmentIntentAssertion.acquire()
                let session = try await CardSession()
                self?.presentmentIntent = intent
                self?.cardSession = session
                var bytesRead = 0
                var notified = false
                for try await event in session.eventStream {
                    switch event {
                    case .sessionStarted:
                        session.alertMessage = alertMessage
                        try await session.startEmulation()
                    case .readerDetected:
                        if !(await session.isEmulationInProgress) { try await session.startEmulation() }
                    case .received(let apdu):
                        let response = emulator.process(apdu.payload)
                        if apdu.payload.count >= 2, apdu.payload[apdu.payload.startIndex + 1] == 0xB0, response.count > 2 {
                            bytesRead += response.count - 2
                            if bytesRead >= ndefLength, !notified { notified = true; onRead() }
                        }
                        try await apdu.respond(response: response)
                    case .readerDeselected:
                        if notified {
                            await session.stopEmulation(status: .success)
                            session.invalidate()
                        }
                    case .sessionInvalidated:
                        onEnd(nil)
                        self?.presentmentIntent = nil
                        return
                    @unknown default:
                        break
                    }
                }
                onEnd(nil)
            } catch {
                onEnd(error)
            }
            self?.presentmentIntent = nil
        }
    }

    public func stop() {
        cardSession?.invalidate()
        task?.cancel()
        presentmentIntent = nil
    }
}
#endif
