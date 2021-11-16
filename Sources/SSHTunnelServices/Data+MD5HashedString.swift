import Crypto
import Foundation

@available(macOS 11, iOS 14, watchOS 7, tvOS 14, *)
public extension Data {
  func md5HashedString() -> String {
    return Crypto.Insecure.MD5.hash(data: self).map { String(format: "%02x", $0) }.joined(separator: ":")
  }
}
