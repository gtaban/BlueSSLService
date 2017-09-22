// swift-tools-version:4.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

#if os(Linux) || os(macOS) || os(iOS) || os(tvOS)
    
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
        .library( name: "TLSService", targets: ["TLSService"]),
        ],
    
    dependencies: packageDependencies,
    
    targets: [
        .target( name: "TLSService", dependencies: ["ServerSecurity"], exclude: ["Certs"]),
        .testTarget( name: "TLSServiceTests", dependencies: ["TLSService", "Socket"], exclude: ["Certs"]),
        ]
)
    
#else
    
fatalError("Unsupported OS")
    
#endif


