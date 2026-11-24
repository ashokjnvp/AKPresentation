import XCTest
import AKSecurity
import AKOpenID4VCI
@testable import AKPresentation

/// Mints test credentials signed by the test PKI.
enum TestCredentials {

    static let issuer = "https://issuer.example.com"

    static var issuerSigner: AKSoftwareJWTSigner {
        try! AKSoftwareJWTSigner(privateKey: AKPrivateKey(pem: TestPKI.issuerSignerKey), algorithm: "ES256")
    }
    static var issuerX5C: AKJSONValue {
        .array([.string(try! AKCertificate(pem: TestPKI.issuerSigner).der.base64EncodedString())])
    }

    static func disclosure(_ salt: String, _ name: String?, _ value: AKJSONValue) throws -> (String, String) {
        var arr: [AKJSONValue] = [.string(salt)]
        if let n = name { arr.append(.string(n)) }
        arr.append(value)
        let encoded = try AKJSONValue.array(arr).jsonData().akBase64URL
        return (encoded, AKDigest.sha256(Data(encoded.utf8)).akBase64URL)
    }

    /// PID-like SD-JWT VC.
    static func sdJWT(holder: AKJWTSigner?, vct: String = "urn:eudi:pid:1") throws -> String {
        let given = try disclosure("s1", "given_name", "Jane")
        let family = try disclosure("s2", "family_name", "Doe")
        let birth = try disclosure("s3", "birthdate", "1990-01-01")
        let street = try disclosure("s4", "street_address", "1 Main St")
        let nat = try disclosure("s5", nil, "IN")
        let over18 = try disclosure("s6", "18", true)
        let ageObject = try disclosure("s7", "age_equal_or_over", ["_sd": [.string(over18.1)]])
        let now = Int(Date().timeIntervalSince1970)
        var claims: [String: AKJSONValue] = [
            "iss": .string(issuer), "vct": .string(vct), "_sd_alg": "sha-256",
            "iat": .number(Double(now)), "exp": .number(Double(now + 86_400)),
            "_sd": [.string(given.1), .string(family.1), .string(birth.1), .string(ageObject.1)],
            "address": ["_sd": [.string(street.1)], "country": "IN"],
            "nationalities": [["...": .string(nat.1)], "FR"]
        ]
        if let h = holder { claims["cnf"] = ["jwk": try AKJSONValue.parse(h.publicJWK().jsonData())] }
        let jwt = try AKCompactJWS.sign(header: ["typ": "dc+sd-jwt", "x5c": issuerX5C], claims: claims, signer: issuerSigner)
        return [jwt, given.0, family.0, birth.0, street.0, nat.0, ageObject.0, over18.0].joined(separator: "~") + "~"
    }

    /// mDL-like mdoc (base64url IssuerSigned).
    static func mdoc(holder: AKJWTSigner, docType: String = "org.iso.18013.5.1.mDL") throws -> String {
        let ns = "org.iso.18013.5.1"
        let elements: [(String, AKCBOR)] = [("family_name", "Doe"), ("given_name", "Jane"), ("age_over_18", true), ("document_number", "DL-123")]
        var items: [AKCBOR] = []
        var digests: [AKCBOR: AKCBOR] = [:]
        for (i, (identifier, value)) in elements.enumerated() {
            let random = try AKBytes.random(count: 16)
            let item: AKCBOR = ["digestID": AKCBOR(i), "random": .byteString(random), "elementIdentifier": .textString(identifier), "elementValue": value]
            let bytes = AKCBOR.encodedCBOR(item)
            items.append(bytes)
            digests[AKCBOR(i)] = .byteString(AKDigest.sha256(bytes.encoded()))
        }
        let deviceKey = try AKCOSEKey.encode(holder.publicKey())
        let now = Date()
        let validity: AKCBOR = ["signed": AKMobileSecurityObject.tdateCBOR(now),
                                "validFrom": AKMobileSecurityObject.tdateCBOR(now.addingTimeInterval(-60)),
                                "validUntil": AKMobileSecurityObject.tdateCBOR(now.addingTimeInterval(86_400))]
        let mso: AKCBOR = ["version": "1.0", "digestAlgorithm": "SHA-256", "docType": .textString(docType),
                           "valueDigests": [.textString(ns): .map(digests)], "deviceKeyInfo": ["deviceKey": deviceKey],
                           "validityInfo": validity]
        let dsKey = try AKPrivateKey(pem: TestPKI.documentSignerKey)
        let ds = try AKCertificate(pem: TestPKI.documentSigner)
        let auth = try AKCOSESign1.sign(payload: AKCBOR.encodedCBOR(mso).encoded(), key: dsKey, algorithm: .es256,
                                        unprotectedHeader: [AKCOSEHeader.x5chain: .byteString(ds.der)])
        return AKMDocCredential.encode(nameSpaces: [ns: items], issuerAuth: auth)
    }

    static func jwtVC(holder: AKJWTSigner) throws -> String {
        let did = "did:jwk:" + (try holder.publicJWK().jsonData()).akBase64URL
        let now = Int(Date().timeIntervalSince1970)
        let claims: [String: AKJSONValue] = [
            "iss": .string(issuer), "sub": .string(did), "iat": .number(Double(now)), "nbf": .number(Double(now)),
            "vc": ["@context": ["https://www.w3.org/2018/credentials/v1"],
                   "type": ["VerifiableCredential", "UniversityDegreeCredential"],
                   "credentialSubject": ["id": .string(did), "degree": "BSc"]]
        ]
        return try AKCompactJWS.sign(header: ["typ": "JWT", "x5c": issuerX5C], claims: claims, signer: issuerSigner)
    }

    static func wallet() throws -> (credentials: [AKHeldCredential], holder: AKSoftwareJWTSigner) {
        let holder = try AKSoftwareJWTSigner.generate()
        let creds = [
            try AKHeldCredential(id: "pid", format: "dc+sd-jwt", raw: .string(try sdJWT(holder: holder)), signer: holder, displayName: "PID"),
            try AKHeldCredential(id: "mdl", format: "mso_mdoc", raw: .string(try mdoc(holder: holder)), signer: holder, displayName: "mDL"),
            try AKHeldCredential(id: "diploma", format: "jwt_vc_json", raw: .string(try jwtVC(holder: holder)), signer: holder, displayName: "Diploma")
        ]
        return (creds, holder)
    }
}

/// In-memory verifier back end.
final class MockVerifier: AKHTTPClient, @unchecked Sendable {

    static let clientId = "x509_san_dns:verifier.example.com"
    let signer: AKSoftwareJWTSigner
    let certificate: AKCertificate
    let encryptionKey: AKPrivateKey
    private let lock = NSLock()
    private(set) var received: [AKHTTPRequest] = []
    var requestObjects: [String: [String: AKJSONValue]] = [:]

    init() throws {
        signer = try AKSoftwareJWTSigner(privateKey: AKPrivateKey(pem: TestPKI.verifierKey), algorithm: "ES256")
        certificate = try AKCertificate(pem: TestPKI.verifierCert)
        encryptionKey = try AKPrivateKey.generate(.ec(.p256))
    }

    var encryptionJWK: AKJSONValue {
        var jwk = try! AKJWK(publicKey: encryptionKey.publicKey, kid: "enc-1")
        jwk.alg = "ECDH-ES"
        jwk.use = "enc"
        return try! AKJSONValue.parse(jwk.jsonData())
    }

    static let pidQuery: AKJSONValue = [
        "credentials": [[
            "id": "pid", "format": "dc+sd-jwt", "meta": ["vct_values": ["urn:eudi:pid:1"]],
            "claims": [["path": ["given_name"]], ["path": ["address", "street_address"]]]
        ]]
    ]

    func requestParameters(responseMode: String = "direct_post", query: AKJSONValue = MockVerifier.pidQuery) -> [String: AKJSONValue] {
        var p: [String: AKJSONValue] = [
            "client_id": .string(Self.clientId), "response_type": "vp_token", "response_mode": .string(responseMode),
            "response_uri": "https://verifier.example.com/response", "nonce": "n-0S6_WzA2Mj", "state": "st-1",
            "dcql_query": query
        ]
        if responseMode.hasSuffix(".jwt") {
            p["client_metadata"] = ["jwks": ["keys": [encryptionJWK]], "encrypted_response_enc_values_supported": ["A256GCM"]]
        }
        return p
    }

    func signedRequest(_ claims: [String: AKJSONValue], typ: String = "oauth-authz-req+jwt", x5c: [AKCertificate]? = nil) throws -> String {
        let chain = (x5c ?? [certificate]).map { AKJSONValue.string($0.der.base64EncodedString()) }
        return try AKCompactJWS.sign(header: ["typ": .string(typ), "x5c": .array(chain)], claims: claims, signer: signer)
    }

    func send(_ request: AKHTTPRequest) async throws -> AKHTTPResponse {
        lock.lock(); defer { lock.unlock() }
        received.append(request)
        switch (request.method, request.url.path) {
        case (.get, let path) where path.hasPrefix("/request/"):
            guard let claims = requestObjects[path] else { return AKHTTPResponse(statusCode: 404) }
            return AKHTTPResponse(statusCode: 200, headers: ["Content-Type": "application/oauth-authz-req+jwt"], body: Data(try signedRequest(claims).utf8))
        case (.post, let path) where path.hasPrefix("/request/"):
            guard var claims = requestObjects[path] else { return AKHTTPResponse(statusCode: 404) }
            let form = request.formParameters
            guard form["wallet_metadata"] != nil else { return AKHTTPResponse(statusCode: 400) }
            if let n = form["wallet_nonce"] { claims["wallet_nonce"] = .string(n) }
            return AKHTTPResponse(statusCode: 200, body: Data(try signedRequest(claims).utf8))
        case (.post, "/response"):
            return AKHTTPResponse(statusCode: 200, headers: ["Content-Type": "application/json"],
                                  body: Data(#"{"redirect_uri":"https://verifier.example.com/done?code=abc"}"#.utf8))
        default:
            return AKHTTPResponse(statusCode: 404)
        }
    }

    var lastResponseForm: [String: String] {
        lock.lock(); defer { lock.unlock() }
        return received.last { $0.url.path == "/response" }?.formParameters ?? [:]
    }
}

func XCTAssertPresentationError<T>(_ expression: @autoclosure () async throws -> T, _ message: String = "",
                                   file: StaticString = #filePath, line: UInt = #line,
                                   _ matches: (AKPresentationError) -> Bool) async {
    do {
        _ = try await expression()
        XCTFail("expected an error. \(message)", file: file, line: line)
    } catch let e as AKPresentationError {
        XCTAssertTrue(matches(e), "unexpected error \(e). \(message)", file: file, line: line)
    } catch {
        XCTFail("unexpected error type \(error). \(message)", file: file, line: line)
    }
}
