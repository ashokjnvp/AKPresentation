import Foundation
import AKSecurity

/// Minimal NDEF encoder (NFC Forum NDEF 1.0).
public struct AKNDEFRecord: Equatable, Sendable {
    public enum TNF: UInt8, Sendable {
        case wellKnown = 0x01
        case media = 0x02
        case external = 0x04
    }

    public let tnf: TNF
    public let type: Data
    public let id: Data
    public let payload: Data

    public init(tnf: TNF, type: String, id: String = "", payload: Data) {
        self.tnf = tnf
        self.type = Data(type.utf8)
        self.id = Data(id.utf8)
        self.payload = payload
    }

    func encoded(first: Bool, last: Bool) -> Data {
        let short = payload.count < 256
        var header = tnf.rawValue
        if first { header |= 0x80 }
        if last { header |= 0x40 }
        if short { header |= 0x10 }
        if !id.isEmpty { header |= 0x08 }
        var out = Data([header, UInt8(type.count)])
        if short {
            out.append(UInt8(payload.count))
        } else {
            let n = UInt32(payload.count)
            out.append(contentsOf: [UInt8(n >> 24), UInt8(n >> 16 & 0xFF), UInt8(n >> 8 & 0xFF), UInt8(n & 0xFF)])
        }
        if !id.isEmpty { out.append(UInt8(id.count)) }
        out.append(type)
        out.append(id)
        out.append(payload)
        return out
    }

    public static func message(_ records: [AKNDEFRecord]) -> Data {
        var out = Data()
        for (i, r) in records.enumerated() { out.append(r.encoded(first: i == 0, last: i == records.count - 1)) }
        return out
    }

    /// Parse an NDEF message (tests / diagnostics).
    public static func parse(_ data: Data) throws -> [AKNDEFRecord] {
        let b = [UInt8](data)
        var i = 0
        var records: [AKNDEFRecord] = []
        while i < b.count {
            let header = b[i]; i += 1
            guard i < b.count else { throw AKPresentationError.session("truncated NDEF") }
            let typeLength = Int(b[i]); i += 1
            var payloadLength = 0
            if header & 0x10 != 0 {
                guard i < b.count else { throw AKPresentationError.session("truncated NDEF") }
                payloadLength = Int(b[i]); i += 1
            } else {
                guard i + 4 <= b.count else { throw AKPresentationError.session("truncated NDEF") }
                payloadLength = Int(b[i]) << 24 | Int(b[i + 1]) << 16 | Int(b[i + 2]) << 8 | Int(b[i + 3]); i += 4
            }
            var idLength = 0
            if header & 0x08 != 0 {
                guard i < b.count else { throw AKPresentationError.session("truncated NDEF") }
                idLength = Int(b[i]); i += 1
            }
            guard i + typeLength + idLength + payloadLength <= b.count, let tnf = TNF(rawValue: header & 0x07) else {
                throw AKPresentationError.session("malformed NDEF record")
            }
            let type = String(decoding: b[i..<i + typeLength], as: UTF8.self); i += typeLength
            let id = String(decoding: b[i..<i + idLength], as: UTF8.self); i += idLength
            let payload = Data(b[i..<i + payloadLength]); i += payloadLength
            records.append(AKNDEFRecord(tnf: tnf, type: type, id: id, payload: payload))
            if header & 0x40 != 0 { break }
        }
        return records
    }
}

/// ISO/IEC 18013-5 NFC static handover (§8.2.2.1): Handover Select with a BLE carrier and the DeviceEngagement.
public enum AKNFCHandover {

    public static let deviceEngagementType = "iso.org:18013:deviceengagement"
    public static let bleOOBType = "application/vnd.bluetooth.le.oob"

    /// Build the Handover Select NDEF message.
    public static func handoverSelect(engagement: AKDeviceEngagement) -> Data {
        // Alternative carrier: CPS active, carrier data ref "0", one auxiliary data ref "mdoc".
        let ac = AKNDEFRecord(tnf: .wellKnown, type: "ac", payload: Data([0x01, 0x01]) + Data("0".utf8) + Data([0x01, 0x04]) + Data("mdoc".utf8))
        let hsPayload = Data([0x15]) + AKNDEFRecord.message([ac])
        let hs = AKNDEFRecord(tnf: .wellKnown, type: "Hs", payload: hsPayload)

        var oob = Data()
        // LE Role: 0x00 = only peripheral (peripheral server mode), 0x01 = only central (central client mode).
        let role: UInt8 = engagement.ble.peripheralServerUUID != nil ? 0x00 : 0x01
        oob.append(contentsOf: [0x02, 0x1C, role])
        if let uuid = engagement.ble.peripheralServerUUID ?? engagement.ble.centralClientUUID {
            oob.append(contentsOf: [0x11, 0x07])
            oob.append(contentsOf: AKUUIDBytes.data(uuid).reversed()) // little-endian
        }
        let ble = AKNDEFRecord(tnf: .media, type: bleOOBType, id: "0", payload: oob)
        let de = AKNDEFRecord(tnf: .external, type: deviceEngagementType, id: "mdoc", payload: engagement.bytes)
        return AKNDEFRecord.message([hs, ble, de])
    }

    /// Handover for the SessionTranscript: [HandoverSelect, null] (static handover).
    public static func sessionHandover(handoverSelect: Data) -> AKCBOR {
        .array([.byteString(handoverSelect), .null])
    }
}

/// NFC Forum Type 4 Tag emulation serving one NDEF message (for CardSession / HCE).
public final class AKType4TagEmulator: @unchecked Sendable {

    public static let ndefAID = Data([0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01])
    static let ccFileID = Data([0xE1, 0x03])
    static let ndefFileID = Data([0xE1, 0x04])

    static let ok = Data([0x90, 0x00])
    static let fileNotFound = Data([0x6A, 0x82])
    static let wrongOffset = Data([0x6B, 0x00])
    static let insNotSupported = Data([0x6D, 0x00])
    static let wrongLength = Data([0x67, 0x00])

    private let ndefFile: Data
    private let ccFile: Data
    private var applicationSelected = false
    private var selectedFile: Data?
    private let lock = NSLock()

    public init(ndefMessage: Data) {
        let n = UInt16(ndefMessage.count)
        ndefFile = Data([UInt8(n >> 8), UInt8(n & 0xFF)]) + ndefMessage
        let maxFile = UInt16(max(ndefFile.count, 0x0400))
        ccFile = Data([0x00, 0x0F, 0x20, 0x7F, 0xFF, 0x7F, 0xFF,
                       0x04, 0x06, 0xE1, 0x04, UInt8(maxFile >> 8), UInt8(maxFile & 0xFF), 0x00, 0xFF])
    }

    /// Process one command APDU and return the response APDU.
    public func process(_ apdu: Data) -> Data {
        lock.lock(); defer { lock.unlock() }
        let b = [UInt8](apdu)
        guard b.count >= 4 else { return Self.wrongLength }
        let ins = b[1], p1 = b[2], p2 = b[3]
        switch ins {
        case 0xA4: // SELECT
            guard b.count >= 5 else { return Self.wrongLength }
            let lc = Int(b[4])
            guard b.count >= 5 + lc else { return Self.wrongLength }
            let data = Data(b[5..<5 + lc])
            if p1 == 0x04 { // by AID
                applicationSelected = data == Self.ndefAID
                selectedFile = nil
                return applicationSelected ? Self.ok : Self.fileNotFound
            }
            if p1 == 0x00, applicationSelected, data == Self.ccFileID || data == Self.ndefFileID {
                selectedFile = data
                return Self.ok
            }
            return Self.fileNotFound
        case 0xB0: // READ BINARY
            guard applicationSelected, let file = selectedFile else { return Self.fileNotFound }
            let content = file == Self.ccFileID ? ccFile : ndefFile
            let offset = Int(p1) << 8 | Int(p2)
            guard offset <= content.count else { return Self.wrongOffset }
            var le = b.count >= 5 ? Int(b[4]) : 256
            if le == 0 { le = 256 }
            let end = min(content.count, offset + le)
            return Data(content[content.startIndex + offset ..< content.startIndex + end]) + Self.ok
        default:
            return Self.insNotSupported
        }
    }
}
