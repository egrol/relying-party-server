//
//  WebAuthnService.swift
//

import Vapor
import AsyncHTTPClient

/// The `WebAuthnService` for issuing challenges to an authenticator and performing attestation and assertion requests.
class WebAuthnService {
    private let fidoUrl: URL
    
    /// Initialize the user service.
    /// - Parameters:
    ///   - fidoUrl: The ``URL`` of the FIDO2 relying party endpoint.
    init(fidoUrl: URL) {
        self.fidoUrl = fidoUrl
    }
    
    /// Create a new authenticator with an attestation object containing a public key for server verification and storage.
    /// - Parameters:
    ///   - token: The ``Token`` for authorizing requests to back-end services.
    ///   - nickname: The friendly name for the registration.
    ///   - clientDataJSON: The base64Url-encoded clientDataJSON that is received from the WebAuthn client.
    ///   - attestationObject: The base64Url-encoded attestationObject that is received from the WebAuthn client.
    ///   - credentialId: The credential identifier that is received from the WebAuthn client.
    func createCredentail(token: Token, nickname: String, clientDataJSON: String, attestationObject: String, credentialId: String) async throws {
        var request = HTTPClientRequest(url: self.fidoUrl.absoluteString + "/attestation/result")
        request.headers.add(name: "content-type", value: "application/json")
        request.headers.add(name: "accept", value: "application/json")
        request.headers.bearerAuthorization = BearerAuthorization(token: token.accessToken)
        request.method = HTTPMethod.POST
        request.body = .bytes(ByteBuffer(string: """
            {
                "type": "public-key",
                "enabled": "true",
                "id": "\(credentialId)",
                "rawId": "\(credentialId)",
                "nickname": "\(nickname)",
                "response": {
                    "clientDataJSON": "\(clientDataJSON)",
                    "attestationObject": "\(attestationObject)"
                }
            }
        """))
        
        let httpClient = HTTPClient(eventLoopGroupProvider: .createNew)
        let response = try await httpClient.execute(request, timeout: .seconds(30))
        let data = try await response.body.collect(upTo: 1024 * 1024)
        
        try await httpClient.shutdown()
        
        // Check the response status for 200 range.
        if !(200...299).contains(response.status.code) {
            throw Abort(HTTPResponseStatus(statusCode: Int(response.status.code)), reason:  String(buffer: data))
        }
    }
    
    /// Verify an authenticator with a signed challenge to the server for verification.
    /// - Parameters:
    ///   - token: The ``Token`` for authorizing requests to back-end services.
    ///   - clientDataJSON: The base64Url-encoded clientDataJson that was received from the WebAuthn client.
    ///   - authenticatorData: Information about the authentication that was produced by the authenticator and verified by the signature.
    ///   - credentialId: The credential identifier that is received from the WebAuthn client.
    ///   - signature: The base64Url-encoded bytes of the signature of the challenge data that was produced by the authenticator.
    func verifyCredentail(token: Token, clientDataJSON: String, authenticatorData: String, credentialId: String, signature: String) async throws -> Data {
        var request = HTTPClientRequest(url: self.fidoUrl.absoluteString + "/assertion/result?returnJwt=true")
        request.headers.add(name: "content-type", value: "application/json")
        request.headers.add(name: "accept", value: "application/json")
        request.headers.bearerAuthorization = BearerAuthorization(token: token.accessToken)
        request.method = HTTPMethod.POST
        request.body = .bytes(ByteBuffer(string: """
            {
               "type": "public-key",
               "id": "\(credentialId)",
               "rawId": "\(credentialId)",
               "response": {
                   "clientDataJSON": "\(clientDataJSON)",
                   "authenticatorData": "\(authenticatorData)",
                   "signature": "\(signature)"
               }
            }
        """))
        
        let httpClient = HTTPClient(eventLoopGroupProvider: .createNew)
        let response = try await httpClient.execute(request, timeout: .seconds(30))
        let data = try await response.body.collect(upTo: 1024 * 1024)
        
        try await httpClient.shutdown()
        
        // Check the response status for 200 range.
        if !(200...299).contains(response.status.code) {
            throw Abort(HTTPResponseStatus(statusCode: Int(response.status.code)), reason:  String(buffer: data))
        }
        
        return Data(buffer: data)
    }
    
    /// Generate a challenge for an authenticator to sign.
    /// - Parameters:
    ///   - token: The ``Token`` for authorizing requests to back-end services.
    ///   - displayName: The display name used by the authenticator for UI representation.
    func generateChallenge(token: Token, displayName: String?, type: ChallengeType) async throws -> String {
        // Set the JSON request body.
        var body = "{"
        if let displayName = displayName {
            body += "\"displayName\": \"\(displayName)\""
        }
        body += "}"
        
        var request = HTTPClientRequest(url: self.fidoUrl.absoluteString + "/\(type.rawValue)/options")
        request.headers.add(name: "content-type", value: "application/json")
        request.headers.add(name: "accept", value: "application/json")
        request.headers.bearerAuthorization = BearerAuthorization(token: token.accessToken)
        request.method = HTTPMethod.POST
        request.body = .bytes(ByteBuffer(string: body))
        
        let httpClient = HTTPClient(eventLoopGroupProvider: .createNew)
        let response = try await httpClient.execute(request, timeout: .seconds(30))
        let data = try await response.body.collect(upTo: 1024 * 1024)
        
        try await httpClient.shutdown()
        
        // Check the response status for 200 range.
        if !(200...299).contains(response.status.code) {
            throw Abort(HTTPResponseStatus(statusCode: Int(response.status.code)), reason:  String(buffer: data))
        }
        
        // Parse for the challenge.
        if let json = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any], let challenge = json["challenge"] as? String {
            return challenge
        }
        
        throw Abort(.badRequest)
    }
}

/// The type of FIDO2 challenge.
enum ChallengeType: String, Codable {
    /// To attest to the provenance of an authenticator.
    case attestation
    
    /// To assert a cryptographically signed object returned by an authenticator.
    case assertion
}
