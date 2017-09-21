//
//  Package.swift
//  SSLService
//
//  Copyright © 2016 IBM. All rights reserved.
//
// 	Licensed under the Apache License, Version 2.0 (the "License");
// 	you may not use this file except in compliance with the License.
// 	You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// 	Unless required by applicable law or agreed to in writing, software
// 	distributed under the License is distributed on an "AS IS" BASIS,
// 	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// 	See the License for the specific language governing permissions and
// 	limitations under the License.
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
