import Foundation
import AKSecurity
import AKOpenID4VCI

/// A credential held by the wallet, decoded for matching and presentation.
public struct AKHeldCredential: Identifiable, Sendable {

    public let id: String
    public let format: String
    /// The credential exactly as issued (string, or object for ldp_vc).
    public let raw: AKJSONValue
    /// Holder key (KB-JWT / DeviceAuth / VP signature). nil for bearer credentials.
    public let signer: AKJWTSigner?
    /// Free-form label for UI.
    public let displayName: String

    public let sdJWT: AKSDJWTVC?
    public let mdoc: AKMDocCredential?
    public let jwtVC: AKW3CJWTCredential?
    public let ldpVC: [String: AKJSONValue]?

    /// Claims used for DCQL matching. SD-JWT: all disclosed claims. mdoc: {namespace: {element: value}}.
    public let claims: AKJSONValue

    public init(id: String, format: String, raw: AKJSONValue, signer: AKJWTSigner?, displayName: String = "") throws {
        self.id = id
        self.format = format
        self.raw = raw
        self.signer = signer
        self.displayName = displayName
        switch format {
        case AKCredentialFormat.sdJWTVC, AKCredentialFormat.sdJWTVCLegacy:
            let sd = try akPresent { try AKSDJWTVC(serialized: raw.stringValue ?? "") }
            self.sdJWT = sd; self.mdoc = nil; self.jwtVC = nil; self.ldpVC = nil
            self.claims = .object(try akPresent { try sd.processedClaims() })
        case AKCredentialFormat.msoMdoc:
            let m = try akPresent { try AKMDocCredential(base64URL: raw.stringValue ?? "") }
            self.sdJWT = nil; self.mdoc = m; self.jwtVC = nil; self.ldpVC = nil
            self.claims = try AKHeldCredential.mdocClaims(m)
        case AKCredentialFormat.jwtVCJSON, AKCredentialFormat.jwtVCJSONLD:
            let vc = try akPresent { try AKW3CJWTCredential(compact: raw.stringValue ?? "") }
            self.sdJWT = nil; self.mdoc = nil; self.jwtVC = vc; self.ldpVC = nil
            self.claims = .object(vc.credential)
        case AKCredentialFormat.ldpVC:
            guard let obj = raw.objectValue else { throw AKPresentationError.invalidRequest("ldp_vc must be an object") }
            self.sdJWT = nil; self.mdoc = nil; self.jwtVC = nil; self.ldpVC = obj
            self.claims = raw
        default:
            throw AKPresentationError.unsupported("credential format \(format)")
        }
    }

    // MARK: Format metadata used by DCQL `meta`

    /// SD-JWT VC `vct`.
    public var vct: String? { sdJWT.flatMap { try? $0.issuerJWT.claims()["vct"]?.stringValue } }

    /// mdoc docType (from the MSO).
    public var docType: String? {
        guard let m = mdoc, let payload = m.issuerAuth.payload,
              let mso = try? AKCBOR.decode(payload).decodeTag24() else { return nil }
        return mso["docType"]?.stringValue
    }

    /// W3C `type` values.
    public var types: [String] {
        if let vc = jwtVC { return vc.types }
        return ldpVC?["type"]?.arrayValue?.compactMap(\.stringValue) ?? []
    }

    /// Issuer certificate chain (SD-JWT / JWT VC `x5c`, mdoc `x5chain`), leaf first.
    public var issuerCertificates: [AKCertificate] {
        if let sd = sdJWT { return (try? sd.issuerJWT.x5c()) ?? [] }
        if let vc = jwtVC { return (try? vc.jws.x5c()) ?? [] }
        if let m = mdoc { return (try? m.issuerAuth.x5chain()) ?? [] }
        return []
    }

    /// Authority Key Identifiers along the issuer chain (for DCQL `trusted_authorities` type `aki`).
    public var authorityKeyIdentifiers: [String] {
        issuerCertificates.compactMap { (try? $0.authorityKeyIdentifier())?.akBase64URL }
    }

    static func mdocClaims(_ m: AKMDocCredential) throws -> AKJSONValue {
        var out: [String: AKJSONValue] = [:]
        for (ns, items) in m.nameSpaces {
            var elements: [String: AKJSONValue] = [:]
            for itemBytes in items {
                let item = try akPresent { try itemBytes.decodeTag24() }
                guard let name = item["elementIdentifier"]?.stringValue, let value = item["elementValue"] else { continue }
                elements[name] = AKIssuedCredential.jsonValue(from: value)
            }
            out[ns] = .object(elements)
        }
        return .object(out)
    }
}

extension AKIssuedCredential {
    /// CBOR → JSON conversion (bytes as base64url, tags unwrapped).
    static func jsonValue(from cbor: AKCBOR) -> AKJSONValue {
        switch cbor {
        case .unsigned, .negative: return cbor.intValue.map { .number(Double($0)) } ?? .null
        case .byteString(let d): return .string(d.akBase64URL)
        case .textString(let s): return .string(s)
        case .array(let a): return .array(a.map(jsonValue(from:)))
        case .map(let m):
            var o: [String: AKJSONValue] = [:]
            for (k, v) in m { o[k.stringValue ?? String(describing: k)] = jsonValue(from: v) }
            return .object(o)
        case .tagged(_, let inner): return jsonValue(from: inner)
        case .bool(let b): return .bool(b)
        case .float(let f): return .number(f)
        case .null, .undefined, .simple: return .null
        }
    }
}
