import Foundation
import AKSecurity
import AKOpenID4VCI

/// Builds SD-JWT VC presentations: path-based selective disclosure and a Key Binding JWT.
public enum AKSDJWTPresenter {

    struct Node {
        let path: [AKJSONValue]
        /// Disclosures that must be revealed for this node to be visible (ancestors first, then itself).
        let required: [String]
    }

    /// Disclosures (encoded strings) needed to reveal `paths`. `all` reveals everything.
    public static func disclosures(for paths: [[AKJSONValue]], in sd: AKSDJWTVC, all: Bool) throws -> [String] {
        if all { return sd.disclosures.map(\.encoded) }
        let alg = try akPresent { try sd.hashAlgorithm() }
        var byDigest: [String: AKSDJWTDisclosure] = [:]
        for d in sd.disclosures {
            let digest = try akPresent { try AKDigest.hash(Data(d.encoded.utf8), using: alg) }.akBase64URL
            byDigest[digest] = d
        }
        var nodes: [Node] = []
        let payload = try akPresent { try sd.issuerJWT.claims() }
        walk(.object(payload), path: [], required: [], byDigest: byDigest, nodes: &nodes, depth: 0)

        var selected = Set<String>()
        for requested in paths {
            for node in nodes where matchesPrefix(requested, of: node.path) {
                selected.formUnion(node.required)
            }
        }
        // Preserve issuance order.
        return sd.disclosures.map(\.encoded).filter(selected.contains)
    }

    static func walk(_ value: AKJSONValue, path: [AKJSONValue], required: [String],
                     byDigest: [String: AKSDJWTDisclosure], nodes: inout [Node], depth: Int) {
        guard depth < 32 else { return }
        switch value {
        case .object(let obj):
            for (k, v) in obj where k != "_sd" && k != "_sd_alg" {
                let p = path + [.string(k)]
                nodes.append(Node(path: p, required: required))
                walk(v, path: p, required: required, byDigest: byDigest, nodes: &nodes, depth: depth + 1)
            }
            for digest in obj["_sd"]?.arrayValue?.compactMap(\.stringValue) ?? [] {
                guard let d = byDigest[digest], let name = d.name else { continue }
                let p = path + [.string(name)]
                let req = required + [d.encoded]
                nodes.append(Node(path: p, required: req))
                walk(d.value, path: p, required: req, byDigest: byDigest, nodes: &nodes, depth: depth + 1)
            }
        case .array(let items):
            var index = 0
            for item in items {
                if let obj = item.objectValue, obj.count == 1, let digest = obj["..."]?.stringValue {
                    guard let d = byDigest[digest], d.name == nil else { continue }
                    let p = path + [.number(Double(index))]
                    let req = required + [d.encoded]
                    nodes.append(Node(path: p, required: req))
                    walk(d.value, path: p, required: req, byDigest: byDigest, nodes: &nodes, depth: depth + 1)
                } else {
                    let p = path + [.number(Double(index))]
                    nodes.append(Node(path: p, required: required))
                    walk(item, path: p, required: required, byDigest: byDigest, nodes: &nodes, depth: depth + 1)
                }
                index += 1
            }
        default:
            break
        }
    }

    /// True if `pattern` (with null wildcards) is a prefix of `path`.
    static func matchesPrefix(_ pattern: [AKJSONValue], of path: [AKJSONValue]) -> Bool {
        guard pattern.count <= path.count else { return false }
        for (p, n) in zip(pattern, path) {
            switch p {
            case .null: if case .number = n { continue } else { return false }
            default: if p != n { return false }
            }
        }
        return true
    }

    /// Build `<issuer-jwt>~<d1>~...~<kb-jwt>`.
    /// - Parameters:
    ///   - audience: the verifier `client_id` (including its prefix) for OpenID4VP.
    ///   - transactionData: base64url transaction_data strings bound to this credential.
    public static func present(_ sd: AKSDJWTVC, paths: [[AKJSONValue]], disclosesAll: Bool, audience: String,
                               nonce: String, signer: AKJWTSigner?, transactionData: [String] = [],
                               issuedAt: Date = Date()) throws -> String {
        let selected = try disclosures(for: paths, in: sd, all: disclosesAll)
        var out = sd.issuerJWT.compact + "~"
        for d in selected { out += d + "~" }
        guard let signer = signer else { return out } // no holder binding requested / possible
        let sdHash = try akPresent { try AKDigest.hash(Data(out.utf8), using: sd.hashAlgorithm()) }.akBase64URL
        var claims: [String: AKJSONValue] = [
            "iat": .number(Double(Int64(issuedAt.timeIntervalSince1970))),
            "aud": .string(audience),
            "nonce": .string(nonce),
            "sd_hash": .string(sdHash)
        ]
        if !transactionData.isEmpty {
            claims["transaction_data_hashes"] = .array(transactionData.map { .string(AKDigest.sha256(Data($0.utf8)).akBase64URL) })
            claims["transaction_data_hashes_alg"] = "sha-256"
        }
        let kb = try akPresent { try AKCompactJWS.sign(header: ["typ": "kb+jwt"], claims: claims, signer: signer) }
        return out + kb
    }
}
