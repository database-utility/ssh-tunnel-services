import Crypto
import Foundation

public extension Curve25519.Signing.PrivateKey {
  init(sshpemRepresentation: String) throws {
    let base64 = sshpemRepresentation.split(separator: "\n").dropFirst().dropLast().joined()
    let data = Data(base64Encoded: String(base64))!
    let lengthRange = data.range(of: Data([0x00, 0x00, 0x00, 0x40]))!
    let range = lengthRange.endIndex..<(lengthRange.endIndex + 32)
    try self.init(rawRepresentation: data[range])
  }
}
