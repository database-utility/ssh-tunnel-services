import Foundation

@available(macOS 11, iOS 14, watchOS 7, tvOS 14, *)
public enum SSHAuthenticationMethod: String, CaseIterable, Identifiable, Encodable {
  case password
  case ed25519Key
  case p256Key
  case p384Key
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
