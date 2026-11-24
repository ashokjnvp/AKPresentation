import Foundation
import AKSecurity
import AKOpenID4VCI

/// Errors raised by AKPresentation.
public enum AKPresentationError: Error, Equatable, Sendable {
    /// The request is malformed or violates the protocol (maps to `invalid_request`).
    case invalidRequest(String)
    /// The verifier could not be authenticated (signature, certificate, client_id binding).
    case untrustedVerifier(String)
    /// The wallet cannot satisfy the request with the credentials it holds.
    case noMatchingCredentials(String)
    /// A requested format, client_id prefix or response mode is not supported.
    case unsupported(String)
    /// The response could not be delivered.
    case responseFailed(String)
    /// Proximity session failure (decryption, transport, CBOR).
    case session(String)
    /// The user declined.
    case userDeclined
    case crypto(AKError)
    case issuance(AKVCIError)

    /// OpenID4VP / OAuth error code to send back to the verifier.
    public var oauthErrorCode: String {
        switch self {
        case .invalidRequest: return "invalid_request"
        case .untrustedVerifier: return "invalid_client"
        case .noMatchingCredentials: return "access_denied"
        case .unsupported(let m) where m.contains("format"): return "vp_formats_not_supported"
        case .unsupported: return "invalid_request"
        case .userDeclined: return "access_denied"
        default: return "server_error"
        }
    }
}

extension AKPresentationError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidRequest(let m): return "Invalid request: \(m)"
        case .untrustedVerifier(let m): return "The verifier could not be trusted: \(m)"
        case .noMatchingCredentials(let m): return "No matching credentials: \(m)"
        case .unsupported(let m): return "Not supported: \(m)"
        case .responseFailed(let m): return "Could not send the response: \(m)"
        case .session(let m): return "Proximity session error: \(m)"
        case .userDeclined: return "The request was declined"
        case .crypto(let e): return e.localizedDescription
        case .issuance(let e): return e.localizedDescription
        }
    }
}

/// Map lower-level errors into AKPresentationError.
@inline(__always)
func akPresent<T>(_ body: () throws -> T) throws -> T {
    do { return try body() }
    catch let e as AKError { throw AKPresentationError.crypto(e) }
    catch let e as AKVCIError { throw AKPresentationError.issuance(e) }
}
