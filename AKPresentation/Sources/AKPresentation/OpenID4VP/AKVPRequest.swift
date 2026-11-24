import Foundation
import AKSecurity
import AKOpenID4VCI

/// Client Identifier Prefixes (OpenID4VP 1.0 §5.9).
public enum AKClientIdPrefix: String, Sendable, CaseIterable {
    case redirectURI = "redirect_uri"
    case x509SanDNS = "x509_san_dns"
    case x509Hash = "x509_hash"
    case decentralizedIdentifier = "decentralized_identifier"
    case verifierAttestation = "verifier_attestation"
    case openIDFederation = "openid_federation"
    case origin = "origin"
    /// No recognised prefix (pre-registered client).
    case preRegistered = ""

    /// Split "x509_san_dns:verifier.example.com" → (.x509SanDNS, "verifier.example.com").
    public static func split(_ clientId: String) -> (AKClientIdPrefix, String) {
        guard let colon = clientId.firstIndex(of: ":") else { return (.preRegistered, clientId) }
        let prefix = String(clientId[..<colon])
        guard let p = AKClientIdPrefix(rawValue: prefix), p != .preRegistered else { return (.preRegistered, clientId) }
        return (p, String(clientId[clientId.index(after: colon)...]))
    }
}

/// How well the verifier was authenticated.
public enum AKVerifierTrust: Sendable, Equatable {
    /// Request signature valid and the verifier's certificate / attestation chains to a trusted anchor.
    case trusted
    /// Signature valid, but no trusted anchor (development / unknown verifier).
    case signatureOnly
    /// Unsigned request (redirect_uri prefix): the verifier identity is just its URL.
    case unsigned
}

/// Verifier metadata (`client_metadata`).
public struct AKVPClientMetadata: Codable, Sendable, Equatable {
    public let jwks: AKJWKSet?
    public let encryptedResponseEncValuesSupported: [String]?
    public let vpFormatsSupported: AKJSONValue?
    public let clientName: String?
    public let logoURI: String?

    enum CodingKeys: String, CodingKey {
        case jwks
        case encryptedResponseEncValuesSupported = "encrypted_response_enc_values_supported"
        case vpFormatsSupported = "vp_formats_supported"
        case clientName = "client_name"
        case logoURI = "logo_uri"
    }
}

/// A validated OpenID4VP Authorization Request.
public struct AKVPAuthorizationRequest: Sendable {
    public let clientId: String
    public let clientIdPrefix: AKClientIdPrefix
    public let clientIdValue: String
    public let responseType: String
    public let responseMode: String
    /// direct_post / direct_post.jwt target.
    public let responseURI: URL?
    /// fragment response target.
    public let redirectURI: URL?
    public let nonce: String
    public let state: String?
    public let dcqlQuery: AKDCQLQuery?
    public let scope: String?
    public let clientMetadata: AKVPClientMetadata?
    /// base64url-encoded transaction data objects.
    public let transactionData: [String]
    public let verifierInfo: [AKJSONValue]
    /// Authentication of the verifier.
    public let trust: AKVerifierTrust
    /// Leaf certificate for x509_* prefixes / verifier attestation subject.
    public let verifierCertificate: AKCertificate?
    /// The raw parameters (for diagnostics / extensions).
    public let parameters: [String: AKJSONValue]

    /// Best human-readable verifier name.
    public var verifierName: String {
        clientMetadata?.clientName ?? verifierCertificate?.subject.organization ?? verifierCertificate?.subject.commonName ?? clientIdValue
    }

    public var isEncryptedResponse: Bool { responseMode.hasSuffix(".jwt") }

    /// Decoded transaction_data entries.
    public var decodedTransactionData: [AKJSONValue] {
        transactionData.compactMap { s in (try? Data(akBase64URL: s)).flatMap { try? AKJSONValue.parse($0) } }
    }

    /// transaction_data strings that reference a credential query id.
    public func transactionData(for queryId: String) -> [String] {
        transactionData.filter { s in
            guard let d = try? Data(akBase64URL: s), let v = try? AKJSONValue.parse(d) else { return false }
            return v["credential_ids"]?.arrayValue?.contains(.string(queryId)) ?? false
        }
    }

    /// The response encryption key chosen from `client_metadata.jwks` (direct_post.jwt / ia_post.jwt).
    public func encryptionKey() throws -> AKJWK {
        guard let keys = clientMetadata?.jwks?.keys, !keys.isEmpty else {
            throw AKPresentationError.invalidRequest("encrypted response requested but client_metadata.jwks is missing")
        }
        let supported: Set<String> = ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A256KW", "RSA-OAEP-256"]
        guard let key = keys.first(where: { ($0.use == nil || $0.use == "enc") && supported.contains($0.alg ?? "ECDH-ES") }) else {
            throw AKPresentationError.unsupported("no usable response encryption key in client_metadata.jwks")
        }
        return key
    }

    /// enc for the encrypted response (default A128GCM).
    public var responseEncryptionEnc: String {
        let wanted = clientMetadata?.encryptedResponseEncValuesSupported ?? ["A128GCM"]
        return ["A128GCM", "A256GCM"].first(where: wanted.contains) ?? "A128GCM"
    }

    /// Where the mdoc OpenID4VPHandover points (response_uri, or redirect_uri for fragment).
    public var handoverResponseURI: String { (responseURI ?? redirectURI)?.absoluteString ?? "" }
}
