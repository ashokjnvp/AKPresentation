import Foundation
import AKSecurity
import AKOpenID4VCI

/// The holder's choice for one credential query.
public struct AKVPSelection: Sendable {
    public let queryId: String
    public let candidate: AKCredentialCandidate

    public init(queryId: String, candidate: AKCredentialCandidate) {
        self.queryId = queryId
        self.candidate = candidate
    }
}

/// Builds the `vp_token` for an OpenID4VP response.
public enum AKVPPresenter {

    /// Default selections: first candidate of each query the match selects.
    public static func defaultSelections(for match: AKDCQLMatch) throws -> [AKVPSelection] {
        guard let ids = match.selectedQueryIds else {
            throw AKPresentationError.noMatchingCredentials("missing: \(match.unmatchedQueryIds.joined(separator: ", "))")
        }
        return ids.compactMap { id in match.candidates[id]?.first.map { AKVPSelection(queryId: id, candidate: $0) } }
    }

    /// `vp_token`: { "<query id>": [presentation, ...] }.
    public static func vpToken(for request: AKVPAuthorizationRequest, selections: [AKVPSelection],
                               now: Date = Date()) throws -> AKJSONValue {
        guard !selections.isEmpty else { throw AKPresentationError.noMatchingCredentials("nothing selected") }
        let queries = Dictionary(uniqueKeysWithValues: (request.dcqlQuery?.credentials ?? []).map { ($0.id, $0) })
        var token: [String: [AKJSONValue]] = [:]
        for selection in selections {
            guard let query = queries[selection.queryId] else {
                throw AKPresentationError.invalidRequest("unknown credential query \(selection.queryId)")
            }
            if let existing = token[selection.queryId], !existing.isEmpty, !(query.multiple ?? false) {
                throw AKPresentationError.invalidRequest("query \(selection.queryId) does not allow multiple credentials")
            }
            let presentation = try present(selection.candidate, query: query, request: request, now: now)
            token[selection.queryId, default: []].append(presentation)
        }
        return .object(token.mapValues { .array($0) })
    }

    static func present(_ candidate: AKCredentialCandidate, query: AKCredentialQuery, request: AKVPAuthorizationRequest,
                        now: Date) throws -> AKJSONValue {
        let credential = candidate.credential
        if query.requiresHolderBinding, credential.signer == nil {
            throw AKPresentationError.noMatchingCredentials("credential \(credential.id) has no holder key")
        }
        switch credential.format {
        case AKCredentialFormat.sdJWTVC, AKCredentialFormat.sdJWTVCLegacy:
            guard let sd = credential.sdJWT else { throw AKPresentationError.invalidRequest("not an SD-JWT") }
            let presentation = try AKSDJWTPresenter.present(
                sd, paths: candidate.claimPaths, disclosesAll: candidate.disclosesAll, audience: request.clientId,
                nonce: request.nonce, signer: query.requiresHolderBinding ? credential.signer : nil,
                transactionData: request.transactionData(for: query.id), issuedAt: now)
            return .string(presentation)

        case AKCredentialFormat.msoMdoc:
            guard let mdoc = credential.mdoc, let docType = credential.docType else {
                throw AKPresentationError.invalidRequest("not an mdoc")
            }
            guard let signer = credential.signer else { throw AKPresentationError.noMatchingCredentials("mdoc has no device key") }
            var thumbprint: Data?
            if request.isEncryptedResponse {
                thumbprint = try akPresent { try Data(akBase64URL: request.encryptionKey().thumbprint()) }
            }
            let transcript = AKSessionTranscript.openID4VP(clientId: request.clientId, nonce: request.nonce,
                                                            jwkThumbprint: thumbprint, responseURI: request.handoverResponseURI)
            var elements: [String: Set<String>] = [:]
            for (ns, els) in candidate.mdocElements { elements[ns] = Set(els.keys) }
            let disclosure = AKMDocDisclosure(credential: mdoc, docType: docType,
                                              elements: candidate.disclosesAll ? [:] : elements, signer: signer)
            let response = try AKDeviceResponseBuilder.deviceResponse([disclosure], sessionTranscript: transcript)
            return .string(response.encoded().akBase64URL)

        case AKCredentialFormat.jwtVCJSON, AKCredentialFormat.jwtVCJSONLD:
            guard let jwt = credential.raw.stringValue else { throw AKPresentationError.invalidRequest("not a JWT VC") }
            guard let signer = credential.signer else { return .string(jwt) }
            return .string(try verifiablePresentationJWT(credentials: [jwt], signer: signer, audience: request.clientId,
                                                         nonce: request.nonce, now: now))

        default:
            throw AKPresentationError.unsupported("presentation format \(credential.format)")
        }
    }

    /// W3C VP as JWT (VCDM 1.1 `vp` claim), holder identified by did:jwk.
    public static func verifiablePresentationJWT(credentials: [String], signer: AKJWTSigner, audience: String,
                                                 nonce: String, now: Date = Date()) throws -> String {
        let jwk = try akPresent { try signer.publicJWK() }
        let did = "did:jwk:" + (try akPresent { try jwk.jsonData() }).akBase64URL
        let iat = Double(Int64(now.timeIntervalSince1970))
        let claims: [String: AKJSONValue] = [
            "iss": .string(did), "aud": .string(audience), "nonce": .string(nonce),
            "iat": .number(iat), "nbf": .number(iat), "exp": .number(iat + 300),
            "jti": .string("urn:uuid:" + UUID().uuidString.lowercased()),
            "vp": .object([
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiablePresentation"],
                "verifiableCredential": .array(credentials.map { .string($0) })
            ])
        ]
        return try akPresent {
            try AKCompactJWS.sign(header: ["typ": "JWT", "kid": .string(did + "#0")], claims: claims, signer: signer)
        }
    }
}
