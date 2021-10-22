// swift-tools-version:5.5
import PackageDescription

let package = Package(
  name: "ssh-tunnel-services",
  platforms: [
    .macOS(.v12),
    .iOS(.v15),
    .watchOS(.v8),
    .tvOS(.v15),
  ],
  products: [
    .library(name: "SSHTunnelServices", targets: ["SSHTunnelServices"]),
  ],
  dependencies: [
    .package(url: "https://github.com/apple/swift-crypto.git", from: "1.1.6"),
    .package(url: "https://github.com/apple/swift-nio.git", from: "2.30.0"),
    .package(url: "https://github.com/apple/swift-nio-ssh.git", from: "0.3.0"),
  ],
  targets: [
    .target(name: "SSHTunnelServices", dependencies: [
      .product(name: "NIO", package: "swift-nio"),
      .product(name: "NIOFoundationCompat", package: "swift-nio"),
      .product(name: "NIOSSH", package: "swift-nio-ssh"),
      .product(name: "Crypto", package: "swift-crypto"),
    ]),
    .testTarget(name: "SSHTunnelServicesTests", dependencies: [
      "SSHTunnelServices"
    ]),
  ]
)
