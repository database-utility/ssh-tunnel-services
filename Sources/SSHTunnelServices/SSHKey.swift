import Crypto
import Foundation

public enum SSHKey {
  case ed25519(Curve25519.Signing.PrivateKey)
  case p256(P256.Signing.PrivateKey)
  case p384(P384.Signing.PrivateKey)
  case p521(P521.Signing.PrivateKey)
  case secureEnclaveP256(SecureEnclave.P256.Signing.PrivateKey)
  
  public var rawRepresentation: Data {
    switch self {
    case .ed25519(let key): return key.rawRepresentation
    case .p256(let key): return key.rawRepresentation
    case .p384(let key): return key.rawRepresentation
    case .p521(let key): return key.rawRepresentation
    case .secureEnclaveP256(let key): return key.dataRepresentation
    }
  }
}
