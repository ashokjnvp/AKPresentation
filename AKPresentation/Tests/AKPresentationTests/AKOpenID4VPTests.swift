import XCTest
import AKSecurity
import AKOpenID4VCI
@testable import AKPresentation

final class AKOpenID4VPTests: XCTestCase {

    var verifier: MockVerifier!
    var trustedConfig: AKVPConfiguration!

    override func setUpWithError() throws {
        verifier = try MockVerifier()
        trustedConfig = AKVPConfiguration(trustedVerifierAnchors: AKTrustStore(anchors: [try AKCertificate(pem: TestPKI.verifierRoot)]))
    }

    func uri(_ params: [String: String]) -> String {
        "openid4vp://?" + AKFormEncoding.encode(params)
    }

    // MARK: Request resolution

    func testSignedRequestByReferenceGET() async throws {
        verifier.requestObjects["/request/1"] = verifier.requestParameters()
        let resolver = AKVPRequestResolver(http: verifier, configuration: trustedConfig)
        let request = try await resolver.resolve(uri(["client_id": MockVerifier.clientId, "request_uri": "https://verifier.example.com/request/1"]))
        XCTAssertEqual(request.clientIdPrefix, .x509SanDNS)
        XCTAssertEqual(request.clientIdValue, "verifier.example.com")
        XCTAssertEqual(request.trust, .trusted)
        XCTAssertEqual(request.verifierName, "Example Verifier GmbH")
        XCTAssertEqual(request.responseMode, "direct_post")
        XCTAssertEqual(request.dcqlQuery?.credentials.first?.id, "pid")
        XCTAssertEqual(request.state, "st-1")
        XCTAssertTrue(AKVPRequestResolver.isPresentationRequest(uri(["client_id": "x", "request_uri": "https://a.b/c"])))
    }

    func testRequestURIMethodPostSendsWalletMetadataAndNonce() async throws {
        verifier.requestObjects["/request/2"] = verifier.requestParameters()
        let resolver = AKVPRequestResolver(http: verifier, configuration: trustedConfig)
        let request = try await resolver.resolve(uri(["client_id": MockVerifier.clientId, "request_uri": "https://verifier.example.com/request/2",
                                                      "request_uri_method": "post"]))
        XCTAssertEqual(request.nonce, "n-0S6_WzA2Mj")
        let post = try XCTUnwrap(verifier.received.first { $0.method == .post })
        let metadata = try AKJSONValue.parse(Data(try XCTUnwrap(post.formParameters["wallet_metadata"]).utf8))
        XCTAssertNotNil(metadata["vp_formats_supported"]?["dc+sd-jwt"])
        XCTAssertNotNil(metadata["vp_formats_supported"]?["mso_mdoc"])
        XCTAssertNotNil(post.formParameters["wallet_nonce"])
    }

    func testUntrustedVerifierPolicy() async throws {
        verifier.requestObjects["/request/1"] = verifier.requestParameters()
        let strict = AKVPRequestResolver(http: verifier, configuration: AKVPConfiguration(trustedVerifierAnchors: AKTrustStore(anchors: [try AKCertificate(pem: TestPKI.iaca)])))
        await XCTAssertPresentationError(try await strict.resolve(self.uri(["client_id": MockVerifier.clientId, "request_uri": "https://verifier.example.com/request/1"]))) {
            if case .untrustedVerifier = $0 { return true }; return false
        }
        let dev = AKVPRequestResolver(http: verifier, configuration: AKVPConfiguration(allowUntrustedVerifiers: true))
        let request = try await dev.resolve(uri(["client_id": MockVerifier.clientId, "request_uri": "https://verifier.example.com/request/1"]))
        XCTAssertEqual(request.trust, .signatureOnly)
    }

    func testSignedRequestChecks() async throws {
        let resolver = AKVPRequestResolver(http: verifier, configuration: trustedConfig)
        let params = verifier.requestParameters()
        func resolveSigned(_ jwt: String, clientId: String = MockVerifier.clientId) async throws -> AKVPAuthorizationRequest {
            try await resolver.resolve(uri(["client_id": clientId, "request": jwt]))
        }
        // Wrong typ
        await XCTAssertPresentationError(try await resolveSigned(verifier.signedRequest(params, typ: "JWT"))) {
            if case .invalidRequest = $0 { return true }; return false
        }
        // Outer client_id mismatch
        await XCTAssertPresentationError(try await resolveSigned(verifier.signedRequest(params), clientId: "x509_san_dns:other.example.com")) {
            if case .invalidRequest = $0 { return true }; return false
        }
        // SAN mismatch
        var other = params
        other["client_id"] = "x509_san_dns:evil.example.com"
        await XCTAssertPresentationError(try await resolveSigned(verifier.signedRequest(other), clientId: "x509_san_dns:evil.example.com")) {
            if case .untrustedVerifier = $0 { return true }; return false
        }
        // x509_hash
        let hash = AKDigest.sha256(verifier.certificate.der).akBase64URL
        var hashed = params
        hashed["client_id"] = .string("x509_hash:" + hash)
        let ok = try await resolveSigned(verifier.signedRequest(hashed), clientId: "x509_hash:" + hash)
        XCTAssertEqual(ok.clientIdPrefix, .x509Hash)
        hashed["client_id"] = "x509_hash:AAAA"
        await XCTAssertPresentationError(try await resolveSigned(verifier.signedRequest(hashed), clientId: "x509_hash:AAAA")) {
            if case .untrustedVerifier = $0 { return true }; return false
        }
        // redirect_uri prefix must not be signed
        var redirect = params
        redirect["client_id"] = "redirect_uri:https://verifier.example.com/response"
        await XCTAssertPresentationError(try await resolveSigned(verifier.signedRequest(redirect), clientId: "redirect_uri:https://verifier.example.com/response")) {
            if case .invalidRequest = $0 { return true }; return false
        }
    }

    func testUnsignedRedirectURIRequest() async throws {
        let resolver = AKVPRequestResolver(http: verifier)
        let query = String(decoding: try MockVerifier.pidQuery.jsonData(), as: UTF8.self)
        let base: [String: String] = [
            "client_id": "redirect_uri:https://verifier.example.com/response", "response_type": "vp_token",
            "response_mode": "direct_post", "response_uri": "https://verifier.example.com/response", "nonce": "abc",
            "dcql_query": query
        ]
        let request = try await resolver.resolve(uri(base))
        XCTAssertEqual(request.trust, .unsigned)
        XCTAssertEqual(request.clientIdPrefix, .redirectURI)

        var mismatched = base
        mismatched["response_uri"] = "https://elsewhere.example.com/response"
        await XCTAssertPresentationError(try await resolver.resolve(self.uri(mismatched))) { if case .invalidRequest = $0 { return true }; return false }
        var noNonce = base
        noNonce["nonce"] = nil
        await XCTAssertPresentationError(try await resolver.resolve(self.uri(noNonce))) { if case .invalidRequest = $0 { return true }; return false }
        var both = base
        both["scope"] = "pid"
        await XCTAssertPresentationError(try await resolver.resolve(self.uri(both))) { if case .invalidRequest = $0 { return true }; return false }
        var unsignedX509 = base
        unsignedX509["client_id"] = MockVerifier.clientId
        await XCTAssertPresentationError(try await resolver.resolve(self.uri(unsignedX509))) { if case .untrustedVerifier = $0 { return true }; return false }
        var badMode = base
        badMode["response_mode"] = "query"
        await XCTAssertPresentationError(try await resolver.resolve(self.uri(badMode))) { if case .unsupported = $0 { return true }; return false }
    }

    // MARK: End to end

    func testDirectPostPresentationEndToEnd() async throws {
        verifier.requestObjects["/request/1"] = verifier.requestParameters()
        let request = try await AKVPRequestResolver(http: verifier, configuration: trustedConfig)
            .resolve(uri(["client_id": MockVerifier.clientId, "request_uri": "https://verifier.example.com/request/1"]))
        let (creds, holder) = try TestCredentials.wallet()
        let match = try AKDCQLMatcher.match(try XCTUnwrap(request.dcqlQuery), credentials: creds)
        let selections = try AKVPPresenter.defaultSelections(for: match)
        let token = try AKVPPresenter.vpToken(for: request, selections: selections)
        let redirect = try await AKVPResponder(http: verifier).submit(vpToken: token, for: request)
        XCTAssertEqual(redirect?.absoluteString, "https://verifier.example.com/done?code=abc")

        // Verifier view
        let form = verifier.lastResponseForm
        XCTAssertEqual(form["state"], "st-1")
        let vpToken = try AKJSONValue.parse(Data(try XCTUnwrap(form["vp_token"]).utf8))
        let presentation = try XCTUnwrap(vpToken["pid"]?[0]?.stringValue)
        let sd = try AKSDJWTVC(serialized: presentation)
        let claims = try sd.processedClaims()
        XCTAssertEqual(claims["given_name"], "Jane")
        XCTAssertEqual(claims["address"]?["street_address"], "1 Main St")
        XCTAssertNil(claims["birthdate"])
        let kb = try AKCompactJWS(compact: XCTUnwrap(sd.keyBindingJWT))
        XCTAssertNoThrow(try kb.verify(with: holder.publicKey()))
        XCTAssertEqual(try kb.claims()["aud"]?.stringValue, MockVerifier.clientId)
        XCTAssertEqual(try kb.claims()["nonce"]?.stringValue, request.nonce)
    }

    func testDirectPostJWTWithMDoc() async throws {
        let mdocQuery: AKJSONValue = ["credentials": [[
            "id": "mdl", "format": "mso_mdoc", "meta": ["doctype_value": "org.iso.18013.5.1.mDL"],
            "claims": [["path": ["org.iso.18013.5.1", "age_over_18"]]]
        ]]]
        verifier.requestObjects["/request/1"] = verifier.requestParameters(responseMode: "direct_post.jwt", query: mdocQuery)
        let request = try await AKVPRequestResolver(http: verifier, configuration: trustedConfig)
            .resolve(uri(["client_id": MockVerifier.clientId, "request_uri": "https://verifier.example.com/request/1"]))
        XCTAssertTrue(request.isEncryptedResponse)
        XCTAssertEqual(request.responseEncryptionEnc, "A256GCM")
        let (creds, holder) = try TestCredentials.wallet()
        let match = try AKDCQLMatcher.match(try XCTUnwrap(request.dcqlQuery), credentials: creds)
        let token = try AKVPPresenter.vpToken(for: request, selections: try AKVPPresenter.defaultSelections(for: match))
        try await AKVPResponder(http: verifier).submit(vpToken: token, for: request)

        // Verifier decrypts and checks the mdoc against the OpenID4VP handover.
        let jwe = try XCTUnwrap(verifier.lastResponseForm["response"])
        XCTAssertNil(verifier.lastResponseForm["vp_token"])
        let (header, plaintext) = try AKJWE.decrypt(jwe, key: .privateKey(verifier.encryptionKey))
        XCTAssertEqual(header["kid"] as? String, "enc-1")
        XCTAssertEqual(header["enc"] as? String, "A256GCM")
        let payload = try AKJSONValue.parse(plaintext)
        XCTAssertEqual(payload["state"], "st-1")
        let deviceResponse = try AKCBOR.decode(Data(akBase64URL: XCTUnwrap(payload["vp_token"]?["mdl"]?[0]?.stringValue)))
        let doc = try XCTUnwrap(deviceResponse["documents"]?.arrayValue?.first)
        let issuerAuth = try AKCOSESign1(cbor: XCTUnwrap(doc["issuerSigned"]?["issuerAuth"]))
        let mso = try AKMDocVerifier.verifyIssuerAuth(issuerAuth, trustStore: AKTrustStore(anchors: [try AKCertificate(pem: TestPKI.iaca)])).mso
        let thumbprint = try Data(akBase64URL: request.encryptionKey().thumbprint())
        let transcript = AKSessionTranscript.openID4VP(clientId: MockVerifier.clientId, nonce: request.nonce,
                                                        jwkThumbprint: thumbprint, responseURI: "https://verifier.example.com/response")
        let authBytes = AKMDocVerifier.deviceAuthenticationBytes(sessionTranscript: transcript, docType: "org.iso.18013.5.1.mDL",
                                                                  deviceNameSpacesBytes: try XCTUnwrap(doc["deviceSigned"]?["nameSpaces"]))
        let sig = try AKCOSESign1(cbor: XCTUnwrap(doc["deviceSigned"]?["deviceAuth"]?["deviceSignature"]))
        XCTAssertNoThrow(try AKMDocVerifier.verifyDeviceSignature(sig, mso: mso, deviceAuthenticationBytes: authBytes))
        XCTAssertEqual(mso.deviceKey, try holder.publicKey())
        let returned = doc["issuerSigned"]?["nameSpaces"]?["org.iso.18013.5.1"]?.arrayValue
        XCTAssertEqual(returned?.count, 1, "only the requested element is returned")
    }

    func testJWTVCPresentationAndErrors() async throws {
        let query: AKJSONValue = ["credentials": [["id": "degree", "format": "jwt_vc_json",
                                                   "meta": ["type_values": [["UniversityDegreeCredential"]]]]]]
        verifier.requestObjects["/request/1"] = verifier.requestParameters(query: query)
        let request = try await AKVPRequestResolver(http: verifier, configuration: trustedConfig)
            .resolve(uri(["client_id": MockVerifier.clientId, "request_uri": "https://verifier.example.com/request/1"]))
        let (creds, holder) = try TestCredentials.wallet()
        let token = try AKVPPresenter.vpToken(for: request, selections: try AKVPPresenter.defaultSelections(
            for: try AKDCQLMatcher.match(try XCTUnwrap(request.dcqlQuery), credentials: creds)))
        let vp = try AKCompactJWS(compact: XCTUnwrap(token["degree"]?[0]?.stringValue))
        XCTAssertNoThrow(try vp.verify(with: holder.publicKey()))
        let c = try vp.claims()
        XCTAssertEqual(c["aud"]?.stringValue, MockVerifier.clientId)
        XCTAssertEqual(c["nonce"]?.stringValue, request.nonce)
        XCTAssertEqual(c["vp"]?["verifiableCredential"]?.arrayValue?.count, 1)

        // Declining sends access_denied.
        try await AKVPResponder(http: verifier).submitError("access_denied", for: request)
        XCTAssertEqual(verifier.lastResponseForm["error"], "access_denied")
        XCTAssertEqual(verifier.lastResponseForm["state"], "st-1")

        // No match.
        let empty = try AKDCQLMatcher.match(try XCTUnwrap(request.dcqlQuery), credentials: [])
        XCTAssertThrowsError(try AKVPPresenter.defaultSelections(for: empty))
    }

    func testFragmentResponse() async throws {
        let resolver = AKVPRequestResolver(http: verifier)
        let query = String(decoding: try MockVerifier.pidQuery.jsonData(), as: UTF8.self)
        let request = try await resolver.resolve(uri([
            "client_id": "redirect_uri:https://verifier.example.com/cb", "response_type": "vp_token",
            "redirect_uri": "https://verifier.example.com/cb", "nonce": "abc", "state": "s", "dcql_query": query
        ]))
        XCTAssertEqual(request.responseMode, "fragment")
        let (creds, _) = try TestCredentials.wallet()
        let token = try AKVPPresenter.vpToken(for: request, selections: try AKVPPresenter.defaultSelections(
            for: try AKDCQLMatcher.match(try XCTUnwrap(request.dcqlQuery), credentials: creds)))
        let url = try await AKVPResponder(http: verifier).submit(vpToken: token, for: request)
        let fragment = try XCTUnwrap(url.flatMap { URLComponents(url: $0, resolvingAgainstBaseURL: false)?.percentEncodedFragment })
        let params = AKFormEncoding.decode(fragment)
        XCTAssertEqual(params["state"], "s")
        XCTAssertNotNil(params["vp_token"])
    }

    func testInteractiveAuthorizationRequest() async throws {
        let resolver = AKVPRequestResolver(http: verifier)
        let endpoint = URL(string: "https://auth.example.com/authorize-challenge")!
        let request = try await resolver.resolveInteractive(["response_type": "vp_token", "response_mode": "ia_post", "nonce": "n",
                                                             "dcql_query": MockVerifier.pidQuery], endpoint: endpoint)
        XCTAssertEqual(request.clientId, "origin:https://auth.example.com")
        XCTAssertEqual(request.responseURI, endpoint)
        let (creds, _) = try TestCredentials.wallet()
        let token = try AKVPPresenter.vpToken(for: request, selections: try AKVPPresenter.defaultSelections(
            for: try AKDCQLMatcher.match(try XCTUnwrap(request.dcqlQuery), credentials: creds)))
        let response = try AKVPResponder.interactiveResponse(vpToken: token, for: request)
        XCTAssertNotNil(response["vp_token"]?["pid"])
        await XCTAssertPresentationError(try await resolver.resolveInteractive(["response_type": "vp_token", "response_mode": "direct_post",
                                                                                "nonce": "n", "dcql_query": MockVerifier.pidQuery], endpoint: endpoint)) {
            if case .unsupported = $0 { return true }; return false
        }
    }
}
