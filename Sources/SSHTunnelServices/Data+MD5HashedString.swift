import Crypto
import Foundation

public extension Data {
  func md5HashedString() -> String {
    return Crypto.Insecure.MD5.hash(data: self).map { String(format: "%02x", $0) }.joined(separator: ":")
  }
}
