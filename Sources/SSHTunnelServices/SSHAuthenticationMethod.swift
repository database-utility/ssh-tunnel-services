import Foundation

/// SSH authentication methods used to authenticate with the SSH server.
@available(macOS 11, iOS 14, watchOS 7, tvOS 14, *)
public enum SSHAuthenticationMethod: String, CaseIterable, Identifiable, Codable {
  /// Password.
  case password
  /// Edwards 25519 curve.
  case ed25519Key
  /// NIST P-256.
  /// Only keys of this type can be saved in the Secure Element.
  case p256Key
  /// NIST P-384.
  case p384Key
  /// NIST P-521.
  case p521Key
  
  public var id: String { rawValue }
  
  public var displayName: String {
    switch self {
    case .password: return "Password"
    case .ed25519Key: return "Ed25519 Key"
    case .p256Key: return "P-256 Key"
    case .p384Key: return "P-384 Key"
    case .p521Key: return "P-521 Key"
    }
  }
}
