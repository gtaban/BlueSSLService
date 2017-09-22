// This source file is part of the Swift.org Server APIs open source project
//
// Copyright (c) 2017 Swift Server API project authors
// Licensed under Apache License v2.0 with Runtime Library Exception
//
// See http://swift.org/LICENSE.txt for license information
//

import PackageDescription

#if os(Linux) || os(macOS) || os(iOS) || os(tvOS)

	let package = Package(
		name: "TLSService",
		targets: [Target(name: "TLSService")],
		dependencies: [
            .Package(url: "https://github.com/gtaban/security.git", majorVersion: 0),
            
            // Fix me!! BlueSocket is a Test-only dependency.
            // When SPM supports Test-only dependency capability, BlueSocket should be removed.
            .Package(url: "https://github.com/gtaban/BlueSocket.git", majorVersion: 0, minor: 13),
			],
		exclude: ["Certs"])
		
	#if os(Linux)
        // module map for OpenSSL libSSL and libcrypto
		package.dependencies.append(
			.Package(url: "https://github.com/IBM-Swift/OpenSSL.git", majorVersion: 0, minor: 3))
		
	#endif
	
#else
	
	fatalError("Unsupported OS")
	
#endif
