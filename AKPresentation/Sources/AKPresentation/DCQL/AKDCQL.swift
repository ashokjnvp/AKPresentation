import Foundation
import AKOpenID4VCI

// MARK: - Model (OpenID4VP 1.0 §6)

public struct AKDCQLQuery: Codable, Equatable, Sendable {
    public let credentials: [AKCredentialQuery]
    public let credentialSets: [AKCredentialSetQuery]?

    enum CodingKeys: String, CodingKey {
        case credentials
        case credentialSets = "credential_sets"
    }

    public init(credentials: [AKCredentialQuery], credentialSets: [AKCredentialSetQuery]? = nil) {
        self.credentials = credentials
        self.credentialSets = credentialSets
    }

    /// Structural validation (§6.1–6.4).
    public func validate() throws {
        guard !credentials.isEmpty else { throw AKPresentationError.invalidRequest("dcql_query.credentials must not be empty") }
        let ids = credentials.map(\.id)
        guard Set(ids).count == ids.count else { throw AKPresentationError.invalidRequest("credential query ids must be unique") }
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")
        for q in credentials {
            guard !q.id.isEmpty, q.id.unicodeScalars.allSatisfy(allowed.contains) else {
                throw AKPresentationError.invalidRequest("invalid credential query id '\(q.id)'")
            }
            if q.claimSets != nil {
                guard let claims = q.claims, !claims.isEmpty else {
                    throw AKPresentationError.invalidRequest("claim_sets requires claims in \(q.id)")
                }
                guard claims.allSatisfy({ $0.id != nil }) else {
                    throw AKPresentationError.invalidRequest("claims need ids when claim_sets is used in \(q.id)")
                }
            }
            for c in q.claims ?? [] where c.path.isEmpty {
                throw AKPresentationError.invalidRequest("empty claims path in \(q.id)")
            }
        }
        for set in credentialSets ?? [] {
            guard !set.options.isEmpty else { throw AKPresentationError.invalidRequest("credential_sets options must not be empty") }
            for option in set.options {
                for id in option where !ids.contains(id) {
                    throw AKPresentationError.invalidRequest("credential_sets references unknown id \(id)")
                }
            }
        }
    }
}

public struct AKTrustedAuthorityQuery: Codable, Equatable, Sendable {
    public let type: String
    public let values: [String]
}

public struct AKClaimsQuery: Codable, Equatable, Sendable {
    public let id: String?
    public let path: [AKJSONValue]
    public let values: [AKJSONValue]?
    /// ISO mdoc only.
    public let intentToRetain: Bool?

    enum CodingKeys: String, CodingKey {
        case id, path, values
        case intentToRetain = "intent_to_retain"
    }

    public init(id: String? = nil, path: [AKJSONValue], values: [AKJSONValue]? = nil, intentToRetain: Bool? = nil) {
        self.id = id
        self.path = path
        self.values = values
        self.intentToRetain = intentToRetain
    }
}

public struct AKCredentialQuery: Codable, Equatable, Sendable {
    public let id: String
    public let format: String
    public let multiple: Bool?
    public let meta: AKJSONValue?
    public let trustedAuthorities: [AKTrustedAuthorityQuery]?
    public let requireCryptographicHolderBinding: Bool?
    public let claims: [AKClaimsQuery]?
    public let claimSets: [[String]]?

    enum CodingKeys: String, CodingKey {
        case id, format, multiple, meta, claims
        case trustedAuthorities = "trusted_authorities"
        case requireCryptographicHolderBinding = "require_cryptographic_holder_binding"
        case claimSets = "claim_sets"
    }

    public init(id: String, format: String, multiple: Bool? = nil, meta: AKJSONValue? = nil,
                trustedAuthorities: [AKTrustedAuthorityQuery]? = nil, requireCryptographicHolderBinding: Bool? = nil,
                claims: [AKClaimsQuery]? = nil, claimSets: [[String]]? = nil) {
        self.id = id
        self.format = format
        self.multiple = multiple
        self.meta = meta
        self.trustedAuthorities = trustedAuthorities
        self.requireCryptographicHolderBinding = requireCryptographicHolderBinding
        self.claims = claims
        self.claimSets = claimSets
    }

    public var requiresHolderBinding: Bool { requireCryptographicHolderBinding ?? true }
}

public struct AKCredentialSetQuery: Codable, Equatable, Sendable {
    public let options: [[String]]
    /// `required` (default true).
    public let requiredFlag: Bool?

    enum CodingKeys: String, CodingKey {
        case options
        case requiredFlag = "required"
    }

    public init(options: [[String]], required: Bool? = nil) {
        self.options = options
        self.requiredFlag = required
    }

    public var isRequired: Bool { requiredFlag ?? true }
}

// MARK: - Claims path pointers (§7)

public enum AKClaimsPath {

    /// Evaluate a path against JSON. `null` selects all array elements, integers index arrays.
    /// Returns (concrete path, value) pairs.
    public static func select(_ path: [AKJSONValue], in root: AKJSONValue) -> [([AKJSONValue], AKJSONValue)] {
        var current: [([AKJSONValue], AKJSONValue)] = [([], root)]
        for component in path {
            var next: [([AKJSONValue], AKJSONValue)] = []
            for (prefix, value) in current {
                switch component {
                case .string(let key):
                    if let v = value[key] { next.append((prefix + [component], v)) }
                case .null:
                    if let arr = value.arrayValue {
                        for (i, v) in arr.enumerated() { next.append((prefix + [.number(Double(i))], v)) }
                    }
                case .number(let n):
                    if let i = Int(exactly: n), i >= 0, let v = value[i] { next.append((prefix + [component], v)) }
                default:
                    break
                }
            }
            current = next
            if current.isEmpty { break }
        }
        return current
    }
}

// MARK: - Matching

/// What will be disclosed from one credential for one credential query.
public struct AKCredentialCandidate: Sendable {
    public let credential: AKHeldCredential
    /// Requested claim paths that are available (concrete, wildcards preserved from the query).
    public let claimPaths: [[AKJSONValue]]
    /// True when the query has no `claims` (the verifier asks for the whole credential).
    public let disclosesAll: Bool
    /// mdoc: namespace → element → intent_to_retain.
    public var mdocElements: [String: [String: Bool]] {
        var out: [String: [String: Bool]] = [:]
        for p in claimPaths where p.count == 2 {
            guard let ns = p[0].stringValue, let el = p[1].stringValue else { continue }
            out[ns, default: [:]][el] = false
        }
        return out
    }
}

/// Matching results for a whole DCQL query.
public struct AKDCQLMatch: Sendable {
    public let query: AKDCQLQuery
    /// credential query id → candidates (in wallet order).
    public let candidates: [String: [AKCredentialCandidate]]

    /// The credential query ids to present (first satisfiable option of each credential set,
    /// or all queries when there are no sets). nil if the request can't be satisfied.
    public var selectedQueryIds: [String]? {
        guard let sets = query.credentialSets, !sets.isEmpty else {
            let all = query.credentials.map(\.id)
            return all.allSatisfy({ !(candidates[$0] ?? []).isEmpty }) ? all : nil
        }
        var ids: [String] = []
        for set in sets {
            if let option = set.options.first(where: { $0.allSatisfy { !(candidates[$0] ?? []).isEmpty } }) {
                for id in option where !ids.contains(id) { ids.append(id) }
            } else if set.isRequired {
                return nil
            }
        }
        return ids.isEmpty ? nil : ids
    }

    public var isSatisfiable: Bool { selectedQueryIds != nil }

    /// Query ids that could not be matched (for UI).
    public var unmatchedQueryIds: [String] {
        query.credentials.map(\.id).filter { (candidates[$0] ?? []).isEmpty }
    }
}

public enum AKDCQLMatcher {

    /// Match a DCQL query against the wallet's credentials.
    public static func match(_ query: AKDCQLQuery, credentials: [AKHeldCredential]) throws -> AKDCQLMatch {
        try query.validate()
        var result: [String: [AKCredentialCandidate]] = [:]
        for q in query.credentials {
            result[q.id] = credentials.compactMap { candidate(for: q, credential: $0) }
        }
        return AKDCQLMatch(query: query, candidates: result)
    }

    static func formatMatches(_ requested: String, _ held: String) -> Bool {
        if requested == held { return true }
        let sdjwt: Set<String> = [AKCredentialFormat.sdJWTVC, AKCredentialFormat.sdJWTVCLegacy]
        return sdjwt.contains(requested) && sdjwt.contains(held)
    }

    static func candidate(for q: AKCredentialQuery, credential c: AKHeldCredential) -> AKCredentialCandidate? {
        guard formatMatches(q.format, c.format) else { return nil }
        if q.requiresHolderBinding, c.signer == nil, c.format != AKCredentialFormat.ldpVC { return nil }
        guard metaMatches(q, c), trustedAuthoritiesMatch(q, c) else { return nil }

        guard let claims = q.claims, !claims.isEmpty else {
            return AKCredentialCandidate(credential: c, claimPaths: [], disclosesAll: true)
        }
        let available = claims.filter { isAvailable($0, in: c) }
        if let sets = q.claimSets {
            let availableIds = Set(available.compactMap(\.id))
            guard let set = sets.first(where: { Set($0).isSubset(of: availableIds) }) else { return nil }
            let chosen = claims.filter { $0.id.map(set.contains) ?? false }
            return AKCredentialCandidate(credential: c, claimPaths: chosen.map(\.path), disclosesAll: false)
        }
        guard available.count == claims.count else { return nil }
        return AKCredentialCandidate(credential: c, claimPaths: claims.map(\.path), disclosesAll: false)
    }

    static func isAvailable(_ claim: AKClaimsQuery, in c: AKHeldCredential) -> Bool {
        let matches = AKClaimsPath.select(claim.path, in: c.claims)
        guard !matches.isEmpty else { return false }
        guard let values = claim.values, !values.isEmpty else { return true }
        return matches.contains { values.contains($0.1) }
    }

    static func metaMatches(_ q: AKCredentialQuery, _ c: AKHeldCredential) -> Bool {
        let meta = q.meta ?? .object([:])
        switch c.format {
        case AKCredentialFormat.sdJWTVC, AKCredentialFormat.sdJWTVCLegacy:
            guard let values = meta["vct_values"]?.arrayValue?.compactMap(\.stringValue) else { return true }
            return c.vct.map(values.contains) ?? false
        case AKCredentialFormat.msoMdoc:
            guard let doctype = meta["doctype_value"]?.stringValue else { return true }
            return c.docType == doctype
        case AKCredentialFormat.jwtVCJSON, AKCredentialFormat.jwtVCJSONLD, AKCredentialFormat.ldpVC:
            guard let alternatives = meta["type_values"]?.arrayValue else { return true }
            let have = Set(c.types)
            return alternatives.contains { alt in
                let needed = Set(alt.arrayValue?.compactMap(\.stringValue) ?? [])
                return !needed.isEmpty && needed.isSubset(of: have)
            }
        default:
            return false
        }
    }

    static func trustedAuthoritiesMatch(_ q: AKCredentialQuery, _ c: AKHeldCredential) -> Bool {
        guard let authorities = q.trustedAuthorities, !authorities.isEmpty else { return true }
        let akis = Set(c.authorityKeyIdentifiers)
        return authorities.contains { ta in
            switch ta.type {
            case "aki": return !akis.isDisjoint(with: ta.values)
            default: return false // etsi_tl / openid_federation need external trust-framework resolution
            }
        }
    }
}
