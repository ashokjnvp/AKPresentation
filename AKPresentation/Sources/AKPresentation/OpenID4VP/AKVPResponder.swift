import Foundation
import AKSecurity
import AKOpenID4VCI

/// Delivers OpenID4VP responses (direct_post, direct_post.jwt, fragment, ia_post, ia_post.jwt).
public struct AKVPResponder: Sendable {

    public let http: AKHTTPClient

    public init(http: AKHTTPClient) { self.http = http }

    /// Send the presentation. Returns a URL the wallet should open afterwards (verifier redirect), if any.
    @discardableResult
    public func submit(vpToken: AKJSONValue, for request: AKVPAuthorizationRequest) async throws -> URL? {
        var payload: [String: AKJSONValue] = ["vp_token": vpToken]
        if let s = request.state { payload["state"] = .string(s) }
        return try await deliver(payload, request: request)
    }

    /// Report an error / refusal to the verifier (e.g. access_denied when the user declines).
    @discardableResult
    public func submitError(_ code: String, description: String? = nil, for request: AKVPAuthorizationRequest) async throws -> URL? {
        var payload: [String: AKJSONValue] = ["error": .string(code)]
        if let d = description { payload["error_description"] = .string(d) }
        if let s = request.state { payload["state"] = .string(s) }
        // Error responses are not encrypted.
        switch request.responseMode {
        case "fragment": return fragmentURL(payload, request: request)
        default: return try await postForm(Self.stringify(payload), to: try target(request))
        }
    }

    /// The `openid4vp_response` object for Interactive Authorization (`ia_post` / `ia_post.jwt`).
    public static func interactiveResponse(vpToken: AKJSONValue, for request: AKVPAuthorizationRequest) throws -> AKJSONValue {
        var payload: [String: AKJSONValue] = ["vp_token": vpToken]
        if let s = request.state { payload["state"] = .string(s) }
        if request.responseMode == "ia_post.jwt" {
            return .object(["response": .string(try encrypt(.object(payload), for: request))])
        }
        return .object(payload)
    }

    // MARK: Internals

    func deliver(_ payload: [String: AKJSONValue], request: AKVPAuthorizationRequest) async throws -> URL? {
        switch request.responseMode {
        case "direct_post":
            return try await postForm(Self.stringify(payload), to: try target(request))
        case "direct_post.jwt":
            let jwe = try Self.encrypt(.object(payload), for: request)
            return try await postForm(["response": jwe], to: try target(request))
        case "fragment":
            return fragmentURL(payload, request: request)
        default:
            throw AKPresentationError.unsupported("response_mode \(request.responseMode)")
        }
    }

    func target(_ request: AKVPAuthorizationRequest) throws -> URL {
        guard let url = request.responseURI else { throw AKPresentationError.invalidRequest("no response_uri") }
        return url
    }

    /// JSON-valued parameters are sent as JSON strings.
    static func stringify(_ payload: [String: AKJSONValue]) -> [String: String] {
        var out: [String: String] = [:]
        for (k, v) in payload {
            if let s = v.stringValue { out[k] = s } else { out[k] = (try? v.jsonData()).map { String(decoding: $0, as: UTF8.self) } ?? "" }
        }
        return out
    }

    static func encrypt(_ payload: AKJSONValue, for request: AKVPAuthorizationRequest) throws -> String {
        let jwk = try request.encryptionKey()
        guard let alg = AKJWEAlgorithm(rawValue: jwk.alg ?? "ECDH-ES") else { throw AKPresentationError.unsupported("JWE alg \(jwk.alg ?? "?")") }
        guard let enc = AKJWEEncryption(rawValue: request.responseEncryptionEnc) else {
            throw AKPresentationError.unsupported("JWE enc \(request.responseEncryptionEnc)")
        }
        var header: [String: Any] = [:]
        if let kid = jwk.kid { header["kid"] = kid }
        let key = try akPresent { try jwk.publicKey() }
        let body = try akPresent { try payload.jsonData() }
        return try akPresent { try AKJWE.encrypt(body, key: .publicKey(key), algorithm: alg, encryption: enc, header: header) }
    }

    func postForm(_ form: [String: String], to url: URL) async throws -> URL? {
        let request = AKHTTPRequest(method: .post, url: url,
                                    headers: ["Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"],
                                    body: Data(AKFormEncoding.encode(form).utf8))
        let response: AKHTTPResponse
        do { response = try await http.send(request) } catch {
            throw AKPresentationError.responseFailed(error.localizedDescription)
        }
        guard response.isSuccess else {
            let body = String(decoding: response.body, as: UTF8.self)
            throw AKPresentationError.responseFailed("HTTP \(response.statusCode) \(body.prefix(200))")
        }
        guard !response.body.isEmpty, let json = try? AKJSONValue.parse(response.body),
              let redirect = json["redirect_uri"]?.stringValue else { return nil }
        return URL(string: redirect)
    }

    func fragmentURL(_ payload: [String: AKJSONValue], request: AKVPAuthorizationRequest) -> URL? {
        guard let base = request.redirectURI, var comps = URLComponents(url: base, resolvingAgainstBaseURL: false) else { return nil }
        comps.percentEncodedFragment = AKFormEncoding.encode(Self.stringify(payload))
        return comps.url
    }
}
