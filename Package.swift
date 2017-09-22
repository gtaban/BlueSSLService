// swift-tools-version:4.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

#if os(Linux) || os(macOS) || os(iOS) || os(tvOS) || os(watchOS)

var packageDependencies: [Package.Dependency] = [
    .package(url: "https://github.com/gtaban/security.git", from: "0.0.4"),
    .package(url: "https://github.com/gtaban/BlueSocket.git", from: "0.13.0") ]
var targetDependencies: [Target.Dependency] = [
    .byNameItem(name: "ServerSecurity"),
    .byNameItem(name: "Socket")]

#if os(Linux)
packageDependencies.append(.package(url: "https://github.com/IBM-Swift/OpenSSL.git", from: "0.3.0"))
targetDependencies.append(.byNameItem(name: "OpenSSL"))
#endif

let package = Package(
    name: "TLSService",

    products: [
        // Products define the executables and libraries produced by a package, and make them visible to other packages.
        .library(
            name: "TLSService",
            targets: ["TLSService"]),
        ],

    // Dependencies declare other packages that this package depends
    dependencies: packageDependencies,

    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages which this package depends on.
        .target(
            name: "TLSService",
            dependencies: targetDependencies,
            exclude: ["Certs"]),
        .testTarget(
            name: "TLSServiceTests",
            dependencies: targetDependencies,
            exclude: ["Certs"]),
        ]
)

#else

fatalError("Unsupported OS")

#endif

