import Foundation
import AKSecurity
import AKOpenID4VCI

/// BLE retrieval options advertised in DeviceEngagement (ISO/IEC 18013-5 §8.2.2.3).
public struct AKBLEOptions: Sendable, Equatable {
    /// mdoc acts as GATT server / peripheral (reader connects to us).
    public let peripheralServerUUID: UUID?
    /// mdoc acts as GATT client / central (we connect to the reader).
    public let centralClientUUID: UUID?

    public init(peripheralServerUUID: UUID? = UUID(), centralClientUUID: UUID? = nil) {
        self.peripheralServerUUID = peripheralServerUUID
        self.centralClientUUID = centralClientUUID
    }

    var cbor: AKCBOR {
        var m: [AKCBOR: AKCBOR] = [0: .bool(peripheralServerUUID != nil), 1: .bool(centralClientUUID != nil)]
        if let u = peripheralServerUUID { m[10] = .byteString(AKUUIDBytes.data(u)) }
        if let u = centralClientUUID { m[11] = .byteString(AKUUIDBytes.data(u)) }
        return .map(m)
    }
}

enum AKUUIDBytes {
    static func data(_ uuid: UUID) -> Data {
        withUnsafeBytes(of: uuid.uuid) { Data($0) }
    }
    static func uuid(_ data: Data) -> UUID? {
        guard data.count == 16 else { return nil }
        let b = [UInt8](data)
        return UUID(uuid: (b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]))
    }
}

/// mdoc DeviceEngagement with its ephemeral device key (EDeviceKey).
public struct AKDeviceEngagement: Sendable {

    public let eDeviceKey: AKPrivateKey
    public let ble: AKBLEOptions
    public let cbor: AKCBOR
    /// Encoded DeviceEngagement.
    public let bytes: Data

    /// - Parameter includeRetrievalMethods: false for NFC engagement (methods travel in the Handover Select).
    public init(ble: AKBLEOptions = AKBLEOptions(), includeRetrievalMethods: Bool = true, curve: AKCurve = .p256) throws {
        let key = try akPresent { try AKPrivateKey.generate(.ec(curve)) }
        let coseKey = try akPresent { try AKCOSEKey.encode(key.publicKey) }
        var m: [AKCBOR: AKCBOR] = [
            0: "1.0",
            1: .array([1, AKCBOR.encodedCBOR(coseKey)])
        ]
        if includeRetrievalMethods {
            m[2] = .array([.array([2, 1, ble.cbor])])
        }
        self.eDeviceKey = key
        self.ble = ble
        self.cbor = .map(m)
        self.bytes = AKCBOR.map(m).encoded()
    }

    /// #6.24(bstr .cbor DeviceEngagement) for the SessionTranscript.
    public var taggedBytes: AKCBOR { .tagged(24, .byteString(bytes)) }

    /// EDeviceKeyBytes = #6.24(bstr .cbor COSE_Key).
    public var eDeviceKeyBytes: AKCBOR { cbor[1]?.arrayValue?[1] ?? .null }

    /// QR code content: "mdoc:" + base64url(DeviceEngagement).
    public var qrCode: String { "mdoc:" + bytes.akBase64URL }

    /// Parse a DeviceEngagement (reader side / tests).
    public static func parse(qrCode: String) throws -> (cbor: AKCBOR, bytes: Data, eDeviceKey: AKPublicKey, ble: AKBLEOptions) {
        guard qrCode.hasPrefix("mdoc:") else { throw AKPresentationError.session("not an mdoc engagement QR code") }
        let bytes = try akPresent { try Data(akBase64URL: String(qrCode.dropFirst(5))) }
        let cbor = try akPresent { try AKCBOR.decode(bytes) }
        guard let security = cbor[1]?.arrayValue, security.count == 2 else { throw AKPresentationError.session("Security missing") }
        let keyCBOR = try akPresent { try security[1].decodeTag24() }
        let key = try akPresent { try AKCOSEKey.decodePublicKey(keyCBOR) }
        var peripheral: UUID?
        var central: UUID?
        for method in cbor[2]?.arrayValue ?? [] {
            guard let m = method.arrayValue, m.count == 3, m[0].intValue == 2 else { continue }
            if let d = m[2][10]?.bytesValue { peripheral = AKUUIDBytes.uuid(d) }
            if let d = m[2][11]?.bytesValue { central = AKUUIDBytes.uuid(d) }
        }
        return (cbor, bytes, key, AKBLEOptions(peripheralServerUUID: peripheral, centralClientUUID: central))
    }

    /// BLE Ident for mdoc central client mode: HKDF-SHA256(EDeviceKeyBytes, "", "BLEIdent", 16).
    public var bleIdent: Data {
        (try? AKKDF.hkdf(inputKeyMaterial: eDeviceKeyBytes.encoded(), salt: Data(), info: Data("BLEIdent".utf8), outputLength: 16)) ?? Data()
    }
}
