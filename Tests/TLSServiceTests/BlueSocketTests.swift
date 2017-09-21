// This source file is part of the Swift.org Server APIs open source project
//
// Copyright (c) 2017 Swift Server API project authors
// Licensed under Apache License v2.0 with Runtime Library Exception
//
// See http://swift.org/LICENSE.txt for license information
//

import XCTest
import Foundation
import Dispatch

#if os(Linux)
	import Glibc
#endif

import Socket
import ServerSecurity

@testable import TLSService

class BlueSocketTests: XCTestCase {

    let QUIT: String = "QUIT"
    let port: Int32  = 1337
    let host: String = "127.0.0.1"
    let path: String = "/tmp/server.TLStest.socket"
    
    func createHelper(family: Socket.ProtocolFamily = .inet) throws -> Socket {
        
        let socket = try Socket.create(family: family)
        XCTAssertNotNil(socket)
        XCTAssertFalse(socket.isConnected)
        XCTAssertTrue(socket.isBlocking)
        
        return socket
    }
    
    func readAndPrint(socket: Socket, data: inout Data) throws -> String? {
        
        data.count = 0
        let	bytesRead = try socket.read(into: &data)
        if bytesRead > 0 {
            
            print("Read \(bytesRead) from socket...")
            
            guard let response = NSString(data: data as Data, encoding: String.Encoding.utf8.rawValue) else {
                
                print("Error accessing received data...")
                XCTFail()
                return nil
            }
            
            print("Response:\n\(response)")
            return String(describing: response)
        }
        
        return nil
    }
    
    func serverHelper(family: Socket.ProtocolFamily = .inet) throws {
        
        #if os(Linux)
            let myCertPath = URL(fileURLWithPath: #file).appendingPathComponent("../../../Certs/Self-Signed/cert.pem").standardized
            let myKeyPath = URL(fileURLWithPath: #file).appendingPathComponent("../../../Certs/Self-Signed/key.pem").standardized

            let config = TLSConfiguration(withCACertificateDirectory: nil, usingCertificateFile: myCertPath.path, withKeyFile: myKeyPath.path, usingSelfSignedCerts: true)
        #else
            let myP12 = URL(fileURLWithPath: #file).appendingPathComponent("../../../Certs/Self-Signed/cert.pfx").standardized
            let myPassword = "sw!ft!sC00l"
            let config = TLSConfiguration(withChainFilePath: myP12.path, withPassword: myPassword, usingSelfSignedCerts: true)
        #endif

        var keepRunning: Bool = true
        var listenSocket: Socket? = nil
        
        do {
            
            try listenSocket = Socket.create(family: family)
            
            guard let listener = listenSocket else {
                
                print("Unable to unwrap socket...")
                XCTFail()
                return
            }
            
            var socket: Socket
            
            // Are we setting uo a TCP or UNIX based server?
            if family == .inet || family == .inet6 {
                
                // Setting up TLS...
                let service = try TLSService(usingConfiguration: config)
                
                listener.TLSdelegate = service
                
                
                // Setting up TCP...
                try listener.listen(on: Int(port), maxBacklogSize: 10)
                
                print("Listening on port: \(port)")
                
                socket = try listener.acceptClientConnection()
                
                print("Accepted connection from: \(socket.remoteHostname) on port \(socket.remotePort), Secure? \(socket.signature!.isSecure)")
                
            } else {
                
                // Setting up UNIX...
                try listener.listen(on: path, maxBacklogSize: 10)
                
                print("Listening on path: \(path)")
                
                socket = try listener.acceptClientConnection()
                
                print("Accepted connection from: \(socket.remotePath!), Secure? \(socket.signature!.isSecure)")
                
            }
            
            try socket.write(from: "Hello, type 'QUIT' to end session\n")
            
            var bytesRead = 0
            repeat {
                
                var readData = Data()
                bytesRead = try socket.read(into: &readData)
                
                if bytesRead > 0 {
                    
                    guard let response = NSString(data: readData, encoding: String.Encoding.utf8.rawValue) else {
                        
                        print("Error decoding response...")
                        readData.count = 0
                        XCTFail()
                        break
                    }
                    
                    if response.hasPrefix(QUIT) {
                        
                        keepRunning = false
                    }
                    
                    // TCP or UNIX?
                    if family == .inet || family == .inet6 {
                        print("Server received from connection at \(socket.remoteHostname):\(socket.remotePort): \(response) ")
                    } else {
                        print("Server received from connection at \(socket.remotePath!): \(response) ")
                    }
                    
                    let reply = "Server response: \n\(response)\n"
                    try socket.write(from: reply)
                    
                }
                
                if bytesRead == 0 {
                    
                    break
                }
                
            } while keepRunning
            
            socket.close()
            XCTAssertFalse(socket.isActive)
            
        } catch let error {
            
            guard let socketError = error as? Socket.Error else {
                
                print("Unexpected error...")
                XCTFail()
                return
            }
            
            // This error is expected when we're shutting it down...
            if socketError.errorCode == Int32(Socket.SOCKET_ERR_WRITE_FAILED) {
                return
            }
            print("serverHelper Error reported: \(socketError.description)")
            XCTFail()
        }
    }
    
    func launchServerHelper(family: Socket.ProtocolFamily = .inet) {
        
        let queue: DispatchQueue? = DispatchQueue.global(qos: .userInteractive)
        guard let pQueue = queue else {
            
            print("Unable to access global interactive QOS queue")
            XCTFail()
            return
        }
        
        pQueue.async { [unowned self] in
            
            do {
                
                try self.serverHelper(family: family)
                
            } catch let error {
                
                guard let socketError = error as? Socket.Error else {
                    
                    print("Unexpected error...")
                    XCTFail()
                    return
                }
                
                print("launchServerHelper Error reported:\n \(socketError.description)")
                XCTFail()
            }
        }
    }

    func testReadWrite() {
        
        let hostname = "127.0.0.1"
        let port: Int32 = 1337
        
        let bufSize = 4096
        var data = Data()
        
        do {
            
            // Launch the server helper...
            launchServerHelper()
            
            // Need to wait for the server to come up...
            #if os(Linux)
                _ = Glibc.sleep(2)
            #else
                _ = Darwin.sleep(2)
            #endif
            
            // Create the signature...
            let signature = try Socket.Signature(protocolFamily: .inet, socketType: .stream, proto: .tcp, hostname: hostname, port: port)!
            
            // Create the socket...
            let socket = try createHelper()
            
            // Defer cleanup...
            defer {
                // Close the socket...
                socket.close()
                XCTAssertFalse(socket.isActive)
            }
            
            #if os(Linux)
                let myCertPath = URL(fileURLWithPath: #file).appendingPathComponent("../../../Certs/Self-Signed/cert.pem").standardized
                let myKeyPath = URL(fileURLWithPath: #file).appendingPathComponent("../../../Certs/Self-Signed/key.pem").standardized

                let config = TLSConfiguration(clientAllowsSelfSignedCertificates: true, withCipherSuite: nil)

//                let config = TLSService.Configuration(withCACertificateDirectory: nil, usingCertificateFile: myCertPath.path, withKeyFile: myKeyPath.path, usingSelfSignedCerts: true)
            #else
                let myP12 = URL(fileURLWithPath: #file).appendingPathComponent("../../../Certs/Self-Signed/cert.pfx").standardized
                let myPassword = "sw!ft!sC00l"

                //let config = TLSService.Configuration(withChainFilePath: myP12, withPassword: myPassword, usingSelfSignedCerts: true, clientAllowsSelfSignedCertificates: true)
                let config = TLSConfiguration(clientAllowsSelfSignedCertificates: true, withCipherSuite: nil)
            #endif
            
            socket.TLSdelegate = try TLSService(usingConfiguration: config)

            // Connect to the server helper...
            try socket.connect(using: signature)
            if !socket.isConnected {
                
                fatalError("Failed to connect to the server...")
            }
            
            print("\nConnected to host: \(hostname):\(port)")
            print("\tSocket signature: \(socket.signature!.description)\n")
            
            _ = try readAndPrint(socket: socket, data: &data)
            
            let hello = "Hello from client..."
            try socket.write(from: hello)
            
            print("Wrote '\(hello)' to socket...")
            
            let response = try readAndPrint(socket: socket, data: &data)
            
            XCTAssertNotNil(response)
            XCTAssertEqual(response, "Server response: \n\(hello)\n")
            
            try socket.write(from: "QUIT")
            
            print("Sent quit to server...")
            
            // Need to wait for the server to go down before continuing...
            #if os(Linux)
                _ = Glibc.sleep(1)
            #else
                _ = Darwin.sleep(1)
            #endif
            
        } catch let error {
            
            // See if it's a socket error or something else...
            guard let socketError = error as? Socket.Error else {
                
                print("Unexpected error...")
                XCTFail()
                return
            }
            
            print("testReadWrite Error reported: \(socketError.description)")
            XCTFail()
        }
        
    }
    
    static var allTests = [
        ("testReadWrite", testReadWrite),
        ]
}

