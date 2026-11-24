import XCTest
import AKSecurity
import AKOpenID4VCI
@testable import AKPresentation

final class AKDCQLTests: XCTestCase {

    func query(_ json: String) throws -> AKDCQLQuery {
        try JSONDecoder().decode(AKDCQLQuery.self, from: Data(json.utf8))
    }

    func testClaimsPathPointer() {
        let doc: AKJSONValue = ["a": ["b": [1, 2, ["c": "x"]]], "list": [["n": 1], ["n": 2]]]
        XCTAssertEqual(AKClaimsPath.select(["a", "b", 1], in: doc).map(\.1), [2])
        XCTAssertEqual(AKClaimsPath.select(["list", .null, "n"], in: doc).map(\.1), [1, 2])
        XCTAssertEqual(AKClaimsPath.select(["list", .null, "n"], in: doc).map(\.0), [["list", 0, "n"], ["list", 1, "n"]])
        XCTAssertTrue(AKClaimsPath.select(["a", "missing"], in: doc).isEmpty)
        XCTAssertTrue(AKClaimsPath.select(["a", "b", 9], in: doc).isEmpty)
        XCTAssertEqual(AKClaimsPath.select(["a", "b", 2, "c"], in: doc).first?.1, "x")
    }

    func testMatchingByFormatAndMeta() throws {
        let (creds, _) = try TestCredentials.wallet()
        let q = try query(#"""
        {"credentials":[
          {"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["given_name"]},{"path":["nationalities",null]}]},
          {"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"},"claims":[{"path":["org.iso.18013.5.1","age_over_18"],"intent_to_retain":false}]},
          {"id":"degree","format":"jwt_vc_json","meta":{"type_values":[["UniversityDegreeCredential"]]}}
        ]}
        """#)
        let match = try AKDCQLMatcher.match(q, credentials: creds)
        XCTAssertEqual(match.candidates["pid"]?.map(\.credential.id), ["pid"])
        XCTAssertEqual(match.candidates["mdl"]?.first?.mdocElements, ["org.iso.18013.5.1": ["age_over_18": false]])
        XCTAssertEqual(match.candidates["degree"]?.first?.disclosesAll, true)
        XCTAssertEqual(match.selectedQueryIds, ["pid", "mdl", "degree"])
        XCTAssertTrue(match.isSatisfiable)
    }

    func testNonMatchingMetaValuesAndMissingClaims() throws {
        let (creds, _) = try TestCredentials.wallet()
        let q = try query(#"""
        {"credentials":[
          {"id":"a","format":"dc+sd-jwt","meta":{"vct_values":["urn:other"]}},
          {"id":"b","format":"dc+sd-jwt","claims":[{"path":["given_name"],"values":["John"]}]},
          {"id":"c","format":"dc+sd-jwt","claims":[{"path":["given_name"],"values":["Jane"]}]},
          {"id":"d","format":"mso_mdoc","meta":{"doctype_value":"org.iso.23220.photoid.1"}},
          {"id":"e","format":"dc+sd-jwt","claims":[{"path":["does_not_exist"]}]}
        ]}
        """#)
        let match = try AKDCQLMatcher.match(q, credentials: creds)
        XCTAssertEqual(Set(match.unmatchedQueryIds), ["a", "b", "d", "e"])
        XCTAssertEqual(match.candidates["c"]?.count, 1)
        XCTAssertNil(match.selectedQueryIds)
    }

    func testClaimSetsAndCredentialSets() throws {
        let (creds, _) = try TestCredentials.wallet()
        let q = try query(#"""
        {"credentials":[
          {"id":"pid","format":"dc+sd-jwt","claims":[
             {"id":"x","path":["nickname"]},{"id":"g","path":["given_name"]},{"id":"f","path":["family_name"]}],
           "claim_sets":[["x"],["g","f"]]},
          {"id":"photo","format":"mso_mdoc","meta":{"doctype_value":"org.iso.23220.photoid.1"}},
          {"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"}}
        ],
        "credential_sets":[{"options":[["pid"]]},{"options":[["photo"],["mdl"]]},{"required":false,"options":[["photo"]]}]}
        """#)
        let match = try AKDCQLMatcher.match(q, credentials: creds)
        XCTAssertEqual(match.candidates["pid"]?.first?.claimPaths, [["given_name"], ["family_name"]])
        XCTAssertEqual(match.selectedQueryIds, ["pid", "mdl"])
    }

    func testHolderBindingRequirement() throws {
        let bearer = try AKHeldCredential(id: "b", format: "dc+sd-jwt", raw: .string(TestCredentials.sdJWT(holder: nil)), signer: nil)
        let required = try query(#"{"credentials":[{"id":"q","format":"dc+sd-jwt"}]}"#)
        XCTAssertTrue(try AKDCQLMatcher.match(required, credentials: [bearer]).candidates["q"]!.isEmpty)
        let optional = try query(#"{"credentials":[{"id":"q","format":"dc+sd-jwt","require_cryptographic_holder_binding":false}]}"#)
        XCTAssertEqual(try AKDCQLMatcher.match(optional, credentials: [bearer]).candidates["q"]?.count, 1)
    }

    func testTrustedAuthoritiesAKI() throws {
        let (creds, _) = try TestCredentials.wallet()
        let aki = try XCTUnwrap(try AKCertificate(pem: TestPKI.issuerSigner).authorityKeyIdentifier()).akBase64URL
        let good = try query(#"{"credentials":[{"id":"q","format":"dc+sd-jwt","trusted_authorities":[{"type":"aki","values":["\#(aki)"]}]}]}"#)
        XCTAssertEqual(try AKDCQLMatcher.match(good, credentials: creds).candidates["q"]?.count, 1)
        let bad = try query(#"{"credentials":[{"id":"q","format":"dc+sd-jwt","trusted_authorities":[{"type":"aki","values":["AAAA"]}]}]}"#)
        XCTAssertEqual(try AKDCQLMatcher.match(bad, credentials: creds).candidates["q"]?.count, 0)
    }

    func testValidationErrors() throws {
        let invalid = [
            #"{"credentials":[]}"#,
            #"{"credentials":[{"id":"a","format":"x"},{"id":"a","format":"y"}]}"#,
            #"{"credentials":[{"id":"bad id","format":"x"}]}"#,
            #"{"credentials":[{"id":"a","format":"x","claim_sets":[["c"]]}]}"#,
            #"{"credentials":[{"id":"a","format":"x"}],"credential_sets":[{"options":[["zzz"]]}]}"#,
            #"{"credentials":[{"id":"a","format":"x","claims":[{"path":[]}]}]}"#
        ]
        for json in invalid {
            XCTAssertThrowsError(try query(json).validate(), json)
        }
    }
}

final class AKSDJWTPresenterTests: XCTestCase {

    func testSelectiveDisclosureByPath() throws {
        let holder = try AKSoftwareJWTSigner.generate()
        let sd = try AKSDJWTVC(serialized: TestCredentials.sdJWT(holder: holder))
        let presentation = try AKSDJWTPresenter.present(sd, paths: [["given_name"], ["address", "street_address"], ["age_equal_or_over", "18"]],
                                                        disclosesAll: false, audience: "x509_san_dns:verifier.example.com",
                                                        nonce: "nonce-1", signer: holder)
        let parsed = try AKSDJWTVC(serialized: presentation)
        let claims = try parsed.processedClaims()
        XCTAssertEqual(claims["given_name"], "Jane")
        XCTAssertNil(claims["family_name"])
        XCTAssertNil(claims["birthdate"])
        XCTAssertEqual(claims["address"]?["street_address"], "1 Main St")
        XCTAssertEqual(claims["age_equal_or_over"]?["18"], true, "parent disclosure must be included automatically")
        XCTAssertEqual(claims["nationalities"], ["FR"])

        let kb = try AKCompactJWS(compact: try XCTUnwrap(parsed.keyBindingJWT))
        XCTAssertEqual(kb.type, "kb+jwt")
        XCTAssertNoThrow(try kb.verify(with: holder.publicKey()))
        let c = try kb.claims()
        XCTAssertEqual(c["aud"], "x509_san_dns:verifier.example.com")
        XCTAssertEqual(c["nonce"], "nonce-1")
        let sdPart = String(presentation[...presentation.lastIndex(of: "~")!])
        XCTAssertEqual(c["sd_hash"]?.stringValue, AKDigest.sha256(Data(sdPart.utf8)).akBase64URL)
    }

    func testWildcardAndDiscloseAll() throws {
        let holder = try AKSoftwareJWTSigner.generate()
        let sd = try AKSDJWTVC(serialized: TestCredentials.sdJWT(holder: holder))
        let wildcard = try AKSDJWTVC(serialized: AKSDJWTPresenter.present(sd, paths: [["nationalities", .null]], disclosesAll: false,
                                                                           audience: "a", nonce: "n", signer: holder))
        XCTAssertEqual(try wildcard.processedClaims()["nationalities"], ["IN", "FR"])
        XCTAssertNil(try wildcard.processedClaims()["given_name"])

        let all = try AKSDJWTVC(serialized: AKSDJWTPresenter.present(sd, paths: [], disclosesAll: true, audience: "a", nonce: "n", signer: holder))
        XCTAssertEqual(all.disclosures.count, sd.disclosures.count)

        let parentOnly = try AKSDJWTVC(serialized: AKSDJWTPresenter.present(sd, paths: [["age_equal_or_over"]], disclosesAll: false,
                                                                             audience: "a", nonce: "n", signer: holder))
        XCTAssertEqual(try parentOnly.processedClaims()["age_equal_or_over"]?["18"], true, "requesting an object reveals its content")
    }

    func testTransactionDataHashesAndNoHolderBinding() throws {
        let holder = try AKSoftwareJWTSigner.generate()
        let sd = try AKSDJWTVC(serialized: TestCredentials.sdJWT(holder: holder))
        let td = try AKJSONValue.object(["type": "payment", "credential_ids": ["pid"], "amount": "10 EUR"]).jsonData().akBase64URL
        let p = try AKSDJWTVC(serialized: AKSDJWTPresenter.present(sd, paths: [["given_name"]], disclosesAll: false, audience: "a",
                                                                    nonce: "n", signer: holder, transactionData: [td]))
        let c = try AKCompactJWS(compact: XCTUnwrap(p.keyBindingJWT)).claims()
        XCTAssertEqual(c["transaction_data_hashes"], [.string(AKDigest.sha256(Data(td.utf8)).akBase64URL)])
        XCTAssertEqual(c["transaction_data_hashes_alg"], "sha-256")

        let bearer = try AKSDJWTPresenter.present(sd, paths: [["given_name"]], disclosesAll: false, audience: "a", nonce: "n", signer: nil)
        XCTAssertTrue(bearer.hasSuffix("~"))
        XCTAssertNil(try AKSDJWTVC(serialized: bearer).keyBindingJWT)
    }
}

final class AKDeviceResponseTests: XCTestCase {

    func testDeviceResponseForOpenID4VP() throws {
        let holder = try AKSoftwareJWTSigner.generate()
        let mdoc = try AKMDocCredential(base64URL: TestCredentials.mdoc(holder: holder))
        let transcript = AKSessionTranscript.openID4VP(clientId: "x509_san_dns:verifier.example.com", nonce: "n1",
                                                        jwkThumbprint: nil, responseURI: "https://verifier.example.com/response")
        let disclosure = AKMDocDisclosure(credential: mdoc, docType: "org.iso.18013.5.1.mDL",
                                          elements: ["org.iso.18013.5.1": ["age_over_18", "given_name"]], signer: holder)
        let response = try AKDeviceResponseBuilder.deviceResponse([disclosure], sessionTranscript: transcript, notReturned: ["org.example.other"])
        let decoded = try AKCBOR.decode(response.encoded())
        XCTAssertEqual(decoded["status"], 0)
        XCTAssertEqual(decoded["version"], "1.0")
        XCTAssertNotNil(decoded["documentErrors"])
        let doc = try XCTUnwrap(decoded["documents"]?.arrayValue?.first)
        XCTAssertEqual(doc["docType"], "org.iso.18013.5.1.mDL")

        // Verifier side: issuer auth, digests of the returned items, device signature.
        let issuerSigned = try XCTUnwrap(doc["issuerSigned"])
        let issuerAuth = try AKCOSESign1(cbor: XCTUnwrap(issuerSigned["issuerAuth"]))
        let result = try AKMDocVerifier.verifyIssuerAuth(issuerAuth, trustStore: AKTrustStore(anchors: [try AKCertificate(pem: TestPKI.iaca)]))
        var returned: [String: [AKCBOR]] = [:]
        for (k, v) in try XCTUnwrap(issuerSigned["nameSpaces"]?.mapValue) { returned[k.stringValue!] = v.arrayValue! }
        let values = try AKMDocVerifier.verifyIssuerSignedItems(returned, mso: result.mso)
        XCTAssertEqual(Set(values["org.iso.18013.5.1"]!.keys), ["age_over_18", "given_name"])

        let deviceSigned = try XCTUnwrap(doc["deviceSigned"])
        let deviceSignature = try AKCOSESign1(cbor: XCTUnwrap(deviceSigned["deviceAuth"]?["deviceSignature"]))
        let authBytes = AKMDocVerifier.deviceAuthenticationBytes(sessionTranscript: transcript, docType: "org.iso.18013.5.1.mDL",
                                                                  deviceNameSpacesBytes: try XCTUnwrap(deviceSigned["nameSpaces"]))
        XCTAssertNoThrow(try AKMDocVerifier.verifyDeviceSignature(deviceSignature, mso: result.mso, deviceAuthenticationBytes: authBytes))

        let otherTranscript = AKSessionTranscript.openID4VP(clientId: "x", nonce: "n1", jwkThumbprint: nil, responseURI: "https://x")
        let otherBytes = AKMDocVerifier.deviceAuthenticationBytes(sessionTranscript: otherTranscript, docType: "org.iso.18013.5.1.mDL",
                                                                   deviceNameSpacesBytes: try XCTUnwrap(deviceSigned["nameSpaces"]))
        XCTAssertThrowsError(try AKMDocVerifier.verifyDeviceSignature(deviceSignature, mso: result.mso, deviceAuthenticationBytes: otherBytes))
    }

    func testOpenID4VPHandoverStructure() {
        let t = AKSessionTranscript.openID4VP(clientId: "c", nonce: "n", jwkThumbprint: Data([1, 2]), responseURI: "https://r")
        XCTAssertEqual(t.arrayValue?[0], .null)
        XCTAssertEqual(t.arrayValue?[1], .null)
        let handover = t.arrayValue![2]
        XCTAssertEqual(handover.arrayValue?.first, "OpenID4VPHandover")
        let info: AKCBOR = ["c", "n", .byteString(Data([1, 2])), "https://r"]
        XCTAssertEqual(handover.arrayValue?[1], .byteString(AKDigest.sha256(info.encoded())))
    }

    func testCOSEAlgorithmMapping() throws {
        XCTAssertEqual(try AKDeviceResponseBuilder.coseAlgorithm(forJWS: "ES256"), -7)
        XCTAssertEqual(try AKDeviceResponseBuilder.coseAlgorithm(forJWS: "ES384"), -35)
        XCTAssertThrowsError(try AKDeviceResponseBuilder.coseAlgorithm(forJWS: "RS256"))
    }
}
