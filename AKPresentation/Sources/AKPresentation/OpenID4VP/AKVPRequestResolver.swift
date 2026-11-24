import Foundation
import AKSecurity
import AKOpenID4VCI

/// Wallet-side policy for OpenID4VP requests.
public struct AKVPConfiguration: Sendable {
    /// Trust anchors for x509_san_dns / x509_hash verifiers (e.g. relying-party access CA).
    public var trustedVerifierAnchors: AKTrustStore?
    /// Trust anchors for Verifier Attestation issuers.
    public var trustedAttestationIssuers: AKTrustStore?
    /// Accept verifiers whose signature is valid but who don't chain to a trusted anchor (development only).
    public var allowUntrustedVerifiers: Bool
    /// Accept unsigned `redirect_uri:` requests.
    public var allowUnsignedRequests: Bool
    /// Holder key algorithms (for wallet_metadata).
    public var holderAlgorithms: [String]
    public var now: @Sendable () -> Date

    public init(trustedVerifierAnchors: AKTrustStore? = nil, trustedAttestationIssuers: AKTrustStore? = nil,
                allowUntrustedVerifiers: Bool = false, allowUnsignedRequests: Bool = true,
                holderAlgorithms: [String] = ["ES256"], now: @escaping @Sendable () -> Date = { Date() }) {
        self.trustedVerifierAnchors = trustedVerifierAnchors
        self.trustedAttestationIssuers = trustedAttestationIssuers
        self.allowUntrustedVerifiers = allowUntrustedVerifiers
        self.allowUnsignedRequests = allowUnsignedRequests
        self.holderAlgorithms = holderAlgorithms
        self.now = now
    }

    public static let supportedResponseModes = ["direct_post", "direct_post.jwt", "fragment"]

    /// Wallet metadata (§10) sent with request_uri_method=post.
    public var walletMetadata: AKJSONValue {
        let algs: AKJSONValue = .array(holderAlgorithms.map { .string($0) })
        let coseAlgs: AKJSONValue = .array(holderAlgorithms.compactMap { try? AKDeviceResponseBuilder.coseAlgorithm(forJWS: $0) }
            .map { .number(Double($0)) })
        var formats: [String: AKJSONValue] = [:]
        formats["dc+sd-jwt"] = .object(["sd-jwt_alg_values": ["ES256", "ES384", "ES512", "EdDSA"], "kb-jwt_alg_values": algs])
        formats["mso_mdoc"] = .object(["issuerauth_alg_values": [-7, -35, -36, -8], "deviceauth_alg_values": coseAlgs])
        formats["jwt_vc_json"] = .object(["alg_values": algs])
        var m: [String: AKJSONValue] = [:]
        m["vp_formats_supported"] = .object(formats)
        m["client_id_prefixes_supported"] = ["redirect_uri", "x509_san_dns", "x509_hash", "decentralized_identifier", "verifier_attestation"]
        m["request_object_signing_alg_values_supported"] = ["ES256", "ES384", "ES512", "EdDSA", "PS256", "RS256"]
        m["response_types_supported"] = ["vp_token"]
        m["response_modes_supported"] = .array(Self.supportedResponseModes.map { .string($0) })
        return .object(m)
    }
}

/// Parses `openid4vp://` (and similar) URIs, fetches and verifies Request Objects, and validates the request.
public struct AKVPRequestResolver: Sendable {

    public static let requestObjectType = "oauth-authz-req+jwt"
    public static let verifierAttestationType = "verifier-attestation+jwt"

    public let http: AKHTTPClient
    public let configuration: AKVPConfiguration

    public init(http: AKHTTPClient, configuration: AKVPConfiguration = AKVPConfiguration()) {
        self.http = http
        self.configuration = configuration
    }

    /// Whether a scanned / opened URI looks like an OpenID4VP request.
    public static func isPresentationRequest(_ uri: String) -> Bool {
        guard let comps = URLComponents(string: uri) else { return false }
        let names = Set((comps.queryItems ?? []).map(\.name))
        return names.contains("client_id") && (names.contains("request_uri") || names.contains("request") || names.contains("response_type"))
    }

    // MARK: Entry points

    public func resolve(_ uri: String) async throws -> AKVPAuthorizationRequest {
        guard let comps = URLComponents(string: uri.trimmingCharacters(in: .whitespacesAndNewlines)) else {
            throw AKPresentationError.invalidRequest("not a valid URI")
        }
        var params: [String: AKJSONValue] = [:]
        for item in comps.queryItems ?? [] { params[item.name] = .string(item.value ?? "") }
        return try await resolve(parameters: params)
    }

    /// Resolve from parameters (URI query, or the `openid4vp_request` object of Interactive Authorization).
    public func resolve(parameters outer: [String: AKJSONValue]) async throws -> AKVPAuthorizationRequest {
        if outer["request"] != nil, outer["request_uri"] != nil {
            throw AKPresentationError.invalidRequest("request and request_uri must not both be present")
        }
        if outer["request_uri_method"] != nil, outer["request_uri"] == nil {
            throw AKPresentationError.invalidRequest("request_uri_method without request_uri")
        }
        if let requestURI = outer["request_uri"]?.stringValue {
            let method = outer["request_uri_method"]?.stringValue ?? "get"
            guard method == "get" || method == "post" else {
                throw AKPresentationError.invalidRequest("invalid_request_uri_method")
            }
            let (jwt, walletNonce) = try await fetchRequestObject(requestURI, post: method == "post")
            return try await verifySigned(jwt, outerClientId: outer["client_id"]?.stringValue, walletNonce: walletNonce)
        }
        if let jwt = outer["request"]?.stringValue {
            return try await verifySigned(jwt, outerClientId: outer["client_id"]?.stringValue, walletNonce: nil)
        }
        // Unsigned request: only for redirect_uri prefix.
        guard let clientId = outer["client_id"]?.stringValue else { throw AKPresentationError.invalidRequest("client_id is missing") }
        let (prefix, _) = AKClientIdPrefix.split(clientId)
        guard prefix == .redirectURI else {
            throw AKPresentationError.untrustedVerifier("client_id prefix \(prefix.rawValue) requires a signed request object")
        }
        guard configuration.allowUnsignedRequests else { throw AKPresentationError.untrustedVerifier("unsigned requests are disabled") }
        return try validate(params: try Self.decodeJSONParameters(outer), trust: .unsigned, certificate: nil)
    }

    /// Resolve the `openid4vp_request` of an Interactive Authorization step (OpenID4VCI §6).
    /// Responses go back to `endpoint` with `ia_post` / `ia_post.jwt`.
    public func resolveInteractive(_ request: AKJSONValue, endpoint: URL) async throws -> AKVPAuthorizationRequest {
        guard var params = request.objectValue else { throw AKPresentationError.invalidRequest("openid4vp_request must be an object") }
        if let jwt = params["request"]?.stringValue {
            return try await verifySigned(jwt, outerClientId: params["client_id"]?.stringValue, walletNonce: nil, interactiveEndpoint: endpoint)
        }
        // Unsigned: the authorization server is authenticated by TLS; bind the audience to its origin.
        if params["client_id"] == nil { params["client_id"] = .string("origin:" + Self.origin(of: endpoint)) }
        return try validate(params: try Self.decodeJSONParameters(params), trust: .unsigned, certificate: nil, interactiveEndpoint: endpoint)
    }

    static func origin(of url: URL) -> String {
        guard let scheme = url.scheme, let host = url.host else { return url.absoluteString }
        return url.port.map { "\(scheme)://\(host):\($0)" } ?? "\(scheme)://\(host)"
    }

    // MARK: Request object retrieval

    func fetchRequestObject(_ uri: String, post: Bool) async throws -> (String, String?) {
        guard let url = URL(string: uri), url.scheme == "https" else {
            throw AKPresentationError.invalidRequest("request_uri must be https")
        }
        var request = AKHTTPRequest(method: post ? .post : .get, url: url, headers: ["Accept": "application/oauth-authz-req+jwt"])
        var walletNonce: String?
        if post {
            let nonce = try akPresent { try AKBytes.random(count: 16) }.akBase64URL
            walletNonce = nonce
            let metadata = String(decoding: try configuration.walletMetadata.jsonData(), as: UTF8.self)
            request.headers["Content-Type"] = "application/x-www-form-urlencoded"
            request.body = Data(AKFormEncoding.encode(["wallet_metadata": metadata, "wallet_nonce": nonce]).utf8)
        }
        let response: AKHTTPResponse
        do { response = try await http.send(request) } catch {
            throw AKPresentationError.invalidRequest("could not fetch request_uri: \(error.localizedDescription)")
        }
        guard response.isSuccess else { throw AKPresentationError.invalidRequest("request_uri returned HTTP \(response.statusCode)") }
        let jwt = String(decoding: response.body, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        return (jwt, walletNonce)
    }

    // MARK: Signed request verification

    func verifySigned(_ jwt: String, outerClientId: String?, walletNonce: String?,
                      interactiveEndpoint: URL? = nil) async throws -> AKVPAuthorizationRequest {
        let jws = try akPresent { try AKCompactJWS(compact: jwt) }
        guard jws.type == Self.requestObjectType else {
            throw AKPresentationError.invalidRequest("request object typ must be \(Self.requestObjectType)")
        }
        let claims = try akPresent { try jws.claims() }
        guard let clientId = claims["client_id"]?.stringValue else { throw AKPresentationError.invalidRequest("request object has no client_id") }
        if let outer = outerClientId, outer != clientId {
            throw AKPresentationError.invalidRequest("client_id in the request object does not match the URI")
        }
        if let n = walletNonce, claims["wallet_nonce"]?.stringValue != n {
            throw AKPresentationError.invalidRequest("wallet_nonce mismatch")
        }
        let (prefix, value) = AKClientIdPrefix.split(clientId)
        let now = configuration.now()
        var trust: AKVerifierTrust = .signatureOnly
        var certificate: AKCertificate?

        switch prefix {
        case .x509SanDNS, .x509Hash:
            let chain = try akPresent { try jws.x5c() }
            guard let leaf = chain.first else { throw AKPresentationError.untrustedVerifier("x5c header missing") }
            try akPresent { try jws.verify(with: leaf.publicKey()) }
            if prefix == .x509SanDNS {
                let sans = try akPresent { try leaf.subjectAlternativeNames() }
                guard sans.contains(where: { if case .dns(let d) = $0 { return d.caseInsensitiveCompare(value) == .orderedSame }; return false }) else {
                    throw AKPresentationError.untrustedVerifier("leaf certificate has no dNSName SAN \(value)")
                }
            } else {
                guard AKDigest.sha256(leaf.der).akBase64URL == value else {
                    throw AKPresentationError.untrustedVerifier("x509_hash does not match the leaf certificate")
                }
            }
            trust = chainTrust(leaf: leaf, chain: chain, store: configuration.trustedVerifierAnchors, now: now)
            certificate = leaf
        case .decentralizedIdentifier:
            guard value.hasPrefix("did:jwk:") else { throw AKPresentationError.unsupported("DID method of \(value)") }
            let key = try akPresent { try AKDefaultIssuerKeyResolver.didJWKPublicKey(value) }
            try akPresent { try jws.verify(with: key) }
        case .verifierAttestation:
            guard let attestationJWT = jws.header["jwt"]?.stringValue else {
                throw AKPresentationError.untrustedVerifier("verifier attestation (jwt header) missing")
            }
            let (key, attTrust, cert) = try verifierAttestation(attestationJWT, clientIdValue: value, now: now)
            try akPresent { try jws.verify(with: key) }
            trust = attTrust
            certificate = cert
            if let uris = try? akPresent({ try AKCompactJWS(compact: attestationJWT).claims() })["redirect_uris"]?.arrayValue?.compactMap(\.stringValue),
               let target = claims["response_uri"]?.stringValue ?? claims["redirect_uri"]?.stringValue, !uris.contains(target) {
                throw AKPresentationError.untrustedVerifier("response target is not in the attested redirect_uris")
            }
        case .redirectURI:
            throw AKPresentationError.invalidRequest("redirect_uri client_id prefix requests must not be signed")
        case .openIDFederation, .origin, .preRegistered:
            throw AKPresentationError.unsupported("client_id prefix '\(prefix.rawValue)'")
        }

        if trust != .trusted && !configuration.allowUntrustedVerifiers {
            throw AKPresentationError.untrustedVerifier("verifier \(clientId) does not chain to a trusted anchor")
        }
        let request = try validate(params: try Self.decodeJSONParameters(claims), trust: trust, certificate: certificate,
                                   interactiveEndpoint: interactiveEndpoint)
        // Without established trust the response target must be on the authenticated DNS name.
        if prefix == .x509SanDNS, trust != .trusted, interactiveEndpoint == nil, let host = (request.responseURI ?? request.redirectURI)?.host,
           host.caseInsensitiveCompare(value) != .orderedSame {
            throw AKPresentationError.untrustedVerifier("response target host \(host) does not match \(value)")
        }
        return request
    }

    func chainTrust(leaf: AKCertificate, chain: [AKCertificate], store: AKTrustStore?, now: Date) -> AKVerifierTrust {
        guard let s = store, !s.anchors.isEmpty else { return .signatureOnly }
        let validator = AKCertificateValidator(trustStore: s, policy: AKValidationPolicy(validationDate: now))
        return (try? validator.validate(leaf, intermediates: Array(chain.dropFirst()))) != nil ? .trusted : .signatureOnly
    }

    func verifierAttestation(_ jwt: String, clientIdValue: String, now: Date) throws -> (AKPublicKey, AKVerifierTrust, AKCertificate?) {
        let att = try akPresent { try AKCompactJWS(compact: jwt) }
        guard att.type == Self.verifierAttestationType else {
            throw AKPresentationError.untrustedVerifier("verifier attestation typ must be \(Self.verifierAttestationType)")
        }
        let chain = try akPresent { try att.x5c() }
        guard let leaf = chain.first else { throw AKPresentationError.untrustedVerifier("verifier attestation has no x5c") }
        try akPresent { try att.verify(with: leaf.publicKey()) }
        let c = try akPresent { try att.claims() }
        guard c["sub"]?.stringValue == clientIdValue else { throw AKPresentationError.untrustedVerifier("attestation sub mismatch") }
        guard let exp = c["exp"]?.doubleValue, Date(timeIntervalSince1970: exp) > now else {
            throw AKPresentationError.untrustedVerifier("verifier attestation expired")
        }
        guard let cnf = c["cnf"]?["jwk"] else { throw AKPresentationError.untrustedVerifier("attestation has no cnf.jwk") }
        let jwk = try akPresent { try JSONDecoder().decode(AKJWK.self, from: cnf.jsonData()) }
        let key = try akPresent { try jwk.publicKey() }
        return (key, chainTrust(leaf: leaf, chain: chain, store: configuration.trustedAttestationIssuers, now: now), leaf)
    }

    // MARK: Parameter validation

    /// URI parameters arrive as strings; JSON-valued parameters are decoded here.
    static func decodeJSONParameters(_ params: [String: AKJSONValue]) throws -> [String: AKJSONValue] {
        var out = params
        for key in ["dcql_query", "client_metadata", "transaction_data", "verifier_info"] {
            if let s = params[key]?.stringValue {
                guard let v = try? AKJSONValue.parse(Data(s.utf8)) else {
                    throw AKPresentationError.invalidRequest("\(key) is not valid JSON")
                }
                out[key] = v
            }
        }
        return out
    }

    func validate(params: [String: AKJSONValue], trust: AKVerifierTrust, certificate: AKCertificate?,
                  interactiveEndpoint: URL? = nil) throws -> AKVPAuthorizationRequest {
        guard let clientId = params["client_id"]?.stringValue, !clientId.isEmpty else {
            throw AKPresentationError.invalidRequest("client_id is missing")
        }
        let (prefix, value) = AKClientIdPrefix.split(clientId)
        guard let responseType = params["response_type"]?.stringValue else { throw AKPresentationError.invalidRequest("response_type is missing") }
        guard responseType == "vp_token" else { throw AKPresentationError.unsupported("response_type \(responseType)") }
        let responseMode = params["response_mode"]?.stringValue ?? "fragment"
        let allowedModes = interactiveEndpoint == nil ? AKVPConfiguration.supportedResponseModes : ["ia_post", "ia_post.jwt"]
        guard allowedModes.contains(responseMode) else {
            throw AKPresentationError.unsupported("response_mode \(responseMode)")
        }
        guard let nonce = params["nonce"]?.stringValue, !nonce.isEmpty else { throw AKPresentationError.invalidRequest("nonce is missing") }

        let responseURI = interactiveEndpoint ?? params["response_uri"]?.stringValue.flatMap(URL.init(string:))
        let redirectURI = params["redirect_uri"]?.stringValue.flatMap(URL.init(string:))
        if interactiveEndpoint != nil {
            // ia_post: the response goes back to the Authorization Challenge Endpoint.
        } else if responseMode.hasPrefix("direct_post") {
            guard let r = responseURI, r.scheme == "https" else {
                throw AKPresentationError.invalidRequest("direct_post requires an https response_uri")
            }
            guard redirectURI == nil else { throw AKPresentationError.invalidRequest("redirect_uri must not be used with response_uri") }
        } else {
            guard redirectURI != nil else { throw AKPresentationError.invalidRequest("fragment response requires redirect_uri") }
        }
        if prefix == .redirectURI, interactiveEndpoint == nil {
            let target = (responseURI ?? redirectURI)?.absoluteString
            guard target == value else { throw AKPresentationError.invalidRequest("redirect_uri client_id must equal the response target") }
        }

        let dcql = params["dcql_query"]
        let scope = params["scope"]?.stringValue
        guard (dcql == nil) != (scope == nil) else {
            throw AKPresentationError.invalidRequest("exactly one of dcql_query and scope is required")
        }
        var query: AKDCQLQuery?
        if let d = dcql {
            query = try AKPJSON.decode(AKDCQLQuery.self, from: d, context: "dcql_query")
            try query?.validate()
        }

        var metadata: AKVPClientMetadata?
        if let m = params["client_metadata"] {
            metadata = try AKPJSON.decode(AKVPClientMetadata.self, from: m, context: "client_metadata")
        }
        let transactionData = params["transaction_data"]?.arrayValue?.compactMap(\.stringValue) ?? []
        for td in transactionData {
            guard let data = try? Data(akBase64URL: td), let obj = try? AKJSONValue.parse(data),
                  obj["type"]?.stringValue != nil, let ids = obj["credential_ids"]?.arrayValue, !ids.isEmpty else {
                throw AKPresentationError.invalidRequest("invalid transaction_data entry")
            }
        }
        let request = AKVPAuthorizationRequest(
            clientId: clientId, clientIdPrefix: prefix, clientIdValue: value, responseType: responseType,
            responseMode: responseMode, responseURI: responseURI, redirectURI: redirectURI, nonce: nonce,
            state: params["state"]?.stringValue, dcqlQuery: query, scope: scope, clientMetadata: metadata,
            transactionData: transactionData, verifierInfo: params["verifier_info"]?.arrayValue ?? [],
            trust: trust, verifierCertificate: certificate, parameters: params)
        if request.isEncryptedResponse { _ = try request.encryptionKey() }
        return request
    }
}

/// JSON decoding helpers.
enum AKPJSON {
    static func decode<T: Decodable>(_ type: T.Type, from value: AKJSONValue, context: String) throws -> T {
        do { return try JSONDecoder().decode(type, from: value.jsonData()) } catch {
            throw AKPresentationError.invalidRequest("\(context): \(error.localizedDescription)")
        }
    }
}

extension AKDefaultIssuerKeyResolver {
    /// did:jwk → public key.
    static func didJWKPublicKey(_ did: String) throws -> AKPublicKey {
        var encoded = String(did.dropFirst("did:jwk:".count))
        if let hash = encoded.firstIndex(of: "#") { encoded = String(encoded[..<hash]) }
        let jwk = try JSONDecoder().decode(AKJWK.self, from: try Data(akBase64URL: encoded))
        return try jwk.publicKey()
    }
}
