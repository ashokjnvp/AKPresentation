import Foundation
import AKSecurity
import AKOpenID4VCI

/// One document request from an ISO/IEC 18013-5 DeviceRequest.
public struct AKMDocDocRequest: Sendable {
    public let docType: String
    /// namespace → element → intentToRetain.
    public let nameSpaces: [String: [String: Bool]]
    /// #6.24(bstr ItemsRequest) as received (needed for reader authentication).
    public let itemsRequestBytes: AKCBOR
    public let readerAuth: AKCOSESign1?
    public let requestInfo: AKCBOR?
}

/// Reader authentication outcome.
public enum AKReaderTrust: Sendable, Equatable {
    /// No readerAuth in the request.
    case anonymous
    /// Signature valid and the chain validates against the trusted reader CAs.
    case trusted(commonName: String?)
    /// Signature valid but the certificate is not trusted (unknown CA).
    case untrusted(commonName: String?)
    /// readerAuth present but invalid — the request should be rejected.
    case invalid(String)
}

/// ISO/IEC 18013-5 DeviceRequest.
public struct AKMDocDeviceRequest: Sendable {
    public let version: String
    public let docRequests: [AKMDocDocRequest]

    public init(cbor: AKCBOR) throws {
        guard let version = cbor["version"]?.stringValue else { throw AKPresentationError.session("DeviceRequest without version") }
        guard version.hasPrefix("1.") else { throw AKPresentationError.unsupported("DeviceRequest version \(version)") }
        guard let list = cbor["docRequests"]?.arrayValue, !list.isEmpty else {
            throw AKPresentationError.session("DeviceRequest without docRequests")
        }
        self.version = version
        self.docRequests = try list.map { entry in
            guard let itemsBytes = entry["itemsRequest"] else { throw AKPresentationError.session("docRequest without itemsRequest") }
            let items = try akPresent { try itemsBytes.decodeTag24() }
            guard let docType = items["docType"]?.stringValue, let nsMap = items["nameSpaces"]?.mapValue else {
                throw AKPresentationError.session("ItemsRequest missing docType or nameSpaces")
            }
            var ns: [String: [String: Bool]] = [:]
            for (k, v) in nsMap {
                guard let name = k.stringValue, let elements = v.mapValue else { throw AKPresentationError.session("bad nameSpaces") }
                var e: [String: Bool] = [:]
                for (ek, ev) in elements {
                    guard let el = ek.stringValue else { continue }
                    e[el] = ev.boolValue ?? false
                }
                ns[name] = e
            }
            let readerAuth = try entry["readerAuth"].map { auth in try akPresent { try AKCOSESign1(cbor: auth) } }
            return AKMDocDocRequest(docType: docType, nameSpaces: ns, itemsRequestBytes: itemsBytes,
                                    readerAuth: readerAuth, requestInfo: items["requestInfo"])
        }
    }

    /// Verify every readerAuth (ReaderAuthentication = ["ReaderAuthentication", SessionTranscript, ItemsRequestBytes]).
    /// The weakest result across documents is returned.
    public func readerTrust(sessionTranscript: AKCBOR, trustStore: AKTrustStore?, now: Date = Date()) -> AKReaderTrust {
        var result: AKReaderTrust = .anonymous
        for doc in docRequests {
            guard let auth = doc.readerAuth else { continue }
            let payload = AKCBOR.encodedCBOR(.array(["ReaderAuthentication", sessionTranscript, doc.itemsRequestBytes])).encoded()
            do {
                let chain = try auth.x5chain()
                guard let leaf = chain.first else { return .invalid("readerAuth has no x5chain") }
                try auth.verify(with: leaf.publicKey(), detachedPayload: payload)
                let cn = leaf.subject.commonName
                var trusted = false
                if let store = trustStore, !store.anchors.isEmpty {
                    let validator = AKCertificateValidator(trustStore: store, policy: AKValidationPolicy(
                        validationDate: now, requiredExtendedKeyUsages: [AKOID.ekuMDLReaderAuth]))
                    trusted = (try? validator.validate(leaf, intermediates: Array(chain.dropFirst()))) != nil
                }
                let r: AKReaderTrust = trusted ? .trusted(commonName: cn) : .untrusted(commonName: cn)
                if case .anonymous = result { result = r } else if case .untrusted = r { result = r }
            } catch {
                return .invalid((error as? LocalizedError)?.errorDescription ?? "\(error)")
            }
        }
        return result
    }
}

/// Session transcripts (ISO/IEC 18013-5 §9.1.5 and OpenID4VP Appendix B.2.6).
public enum AKSessionTranscript {

    /// [DeviceEngagementBytes, EReaderKeyBytes, Handover] for proximity flows (QR handover = null).
    public static func proximity(deviceEngagementBytes: AKCBOR, eReaderKeyBytes: AKCBOR, handover: AKCBOR) -> AKCBOR {
        .array([deviceEngagementBytes, eReaderKeyBytes, handover])
    }

    /// OpenID4VP (redirect-based) handover:
    /// ["OpenID4VPHandover", SHA-256(cbor([clientId, nonce, jwkThumbprint / null, responseUri]))].
    public static func openID4VP(clientId: String, nonce: String, jwkThumbprint: Data?, responseURI: String) -> AKCBOR {
        let info: AKCBOR = .array([.textString(clientId), .textString(nonce),
                                   jwkThumbprint.map { AKCBOR.byteString($0) } ?? .null, .textString(responseURI)])
        let handover: AKCBOR = .array(["OpenID4VPHandover", .byteString(AKDigest.sha256(info.encoded()))])
        return .array([.null, .null, handover])
    }

    /// #6.24(bstr .cbor SessionTranscript)
    public static func bytes(_ transcript: AKCBOR) -> Data { AKCBOR.encodedCBOR(transcript).encoded() }
}

/// What the holder agreed to disclose from one mdoc.
public struct AKMDocDisclosure: Sendable {
    public let credential: AKMDocCredential
    public let docType: String
    /// namespace → element identifiers. Empty map = disclose everything in the credential.
    public let elements: [String: Set<String>]
    public let signer: AKJWTSigner

    public init(credential: AKMDocCredential, docType: String, elements: [String: Set<String>], signer: AKJWTSigner) {
        self.credential = credential
        self.docType = docType
        self.elements = elements
        self.signer = signer
    }
}

/// Builds ISO/IEC 18013-5 DeviceResponse structures.
public enum AKDeviceResponseBuilder {

    public static func coseAlgorithm(forJWS alg: String) throws -> Int {
        switch alg {
        case "ES256", "BP256R1": return -7
        case "ES384", "BP384R1": return -35
        case "ES512", "BP512R1": return -36
        case "EdDSA", "Ed25519", "Ed448": return -8
        default: throw AKPresentationError.unsupported("device signing alg \(alg)")
        }
    }

    /// COSE_Sign1 with detached payload, signed by any AKJWTSigner (software or Secure Enclave).
    public static func deviceSignature(payload: Data, signer: AKJWTSigner) throws -> AKCOSESign1 {
        let protected = AKCBOR.map([1: AKCBOR(try coseAlgorithm(forJWS: signer.algorithm))]).encoded()
        let toBeSigned = AKCBOR.array(["Signature1", .byteString(protected), .byteString(Data()), .byteString(payload)]).encoded()
        let signature = try akPresent { try signer.sign(toBeSigned) }
        return AKCOSESign1(protectedHeaderBytes: protected, unprotectedHeader: [:], payload: nil, signature: signature)
    }

    /// One Document (issuerSigned filtered to the approved elements + deviceSigned).
    public static func document(_ d: AKMDocDisclosure, sessionTranscript: AKCBOR) throws -> AKCBOR {
        var ns: [AKCBOR: AKCBOR] = [:]
        for (name, items) in d.credential.nameSpaces {
            let kept: [AKCBOR]
            if d.elements.isEmpty {
                kept = items
            } else {
                guard let wanted = d.elements[name], !wanted.isEmpty else { continue }
                kept = try items.filter { item in
                    let decoded = try akPresent { try item.decodeTag24() }
                    return decoded["elementIdentifier"]?.stringValue.map(wanted.contains) ?? false
                }
            }
            if !kept.isEmpty { ns[.textString(name)] = .array(kept) }
        }
        let deviceNameSpacesBytes = AKCBOR.encodedCBOR(.map([:]))
        let authBytes = AKMDocVerifier.deviceAuthenticationBytes(sessionTranscript: sessionTranscript, docType: d.docType,
                                                                  deviceNameSpacesBytes: deviceNameSpacesBytes)
        let signature = try deviceSignature(payload: authBytes, signer: d.signer)
        return [
            "docType": .textString(d.docType),
            "issuerSigned": ["nameSpaces": .map(ns), "issuerAuth": d.credential.issuerAuth.cbor],
            "deviceSigned": ["nameSpaces": deviceNameSpacesBytes, "deviceAuth": ["deviceSignature": signature.cbor]]
        ]
    }

    /// DeviceResponse. `notReturned` doc types are reported in documentErrors (error code 0, "data not returned").
    public static func deviceResponse(_ disclosures: [AKMDocDisclosure], sessionTranscript: AKCBOR,
                                      notReturned: [String] = []) throws -> AKCBOR {
        var response: [AKCBOR: AKCBOR] = ["version": "1.0", "status": 0]
        if !disclosures.isEmpty {
            response["documents"] = .array(try disclosures.map { try document($0, sessionTranscript: sessionTranscript) })
        }
        if !notReturned.isEmpty {
            response["documentErrors"] = .array(notReturned.map { AKCBOR.map([.textString($0): 0]) })
        }
        return .map(response)
    }

    /// DeviceResponse with a non-zero status and no documents (e.g. 10 = general error).
    public static func errorResponse(status: Int) -> AKCBOR {
        ["version": "1.0", "status": AKCBOR(status)]
    }
}
