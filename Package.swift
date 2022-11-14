// swift-tools-version: 5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Relying Party Server",
    platforms: [.macOS(.v12)],
    products: [
        .executable(
            name: "RelyingPartyServer",
            targets: ["RelyingPartyServer"])
    ],
    dependencies: [
        // 💧 A server-side Swift web framework.
        .package(url: "https://github.com/vapor/vapor.git", from: "4.0.0"),
    ],
    targets: [
        .executableTarget(
            name: "RelyingPartyServer",
            dependencies: [
                .product(name: "Vapor", package: "vapor"),
        ]),
        .testTarget(
            name: "RelyingPartyServerTests",
            dependencies: [
                .target(name: "RelyingPartyServer"),
                .product(name: "XCTVapor", package: "vapor"),
        ])
    ]
)
