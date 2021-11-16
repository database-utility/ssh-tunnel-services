import XCTest
@testable import SSHTunnelServices

// TODO: finish tests
// TODO: finish error handling

final class SSHTunnelTests: XCTestCase {
  func testIncorrectCredentials() throws {
    XCTAssertNoThrow(
      try SSHTunnel(
        host: "localhost",
        port: 22,
        username: "root",
        password: "incorrect password",
        privateKey: nil,
        targetHost: "127.1",
        targetPort: 1234
      )
    )
    
    // XCTAssertEqual(tunnel.localPort, -1)
  }
}
