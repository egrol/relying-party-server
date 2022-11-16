//
//  TokenService.swift
//

import Vapor
import AsyncHTTPClient

/// The `TokenService` obtains a new OAuth token from the authorization server.
class TokenService {
    /// The base ``URL`` for the host.
    let baseURL: URL
    
    /// The client identifier issued to the client for perform operations on behalf of a user.
    let clientId: String
    
    /// The client secret.
    let clientSecret: String
    
    /// Initialize the token service.
    /// - Parameters:
    ///   - baseURL: The base ``URL`` for the host.
    ///   - clientId: The client identifier issued to the client for perform operations on behalf of a user.
    ///   - clientSecret: The client secret.
    init(baseURL: URL, clientId: String, clientSecret: String) {
        self.baseURL = baseURL.appendingPathComponent("/v1.0/endpoint/default/token")
        self.clientId = clientId
        self.clientSecret = clientSecret
    }

    /// Authorize an API client credentials grant type returning an OIDC token
    /// - Returns: An instance of a ``Token``.
    func clientCredentials() async throws -> Token {
        var request = HTTPClientRequest(url: self.baseURL.absoluteString)
        request.headers.add(name: "content-type", value: "application/x-www-form-urlencoded")
        request.method = HTTPMethod.POST
        request.body = .bytes(ByteBuffer(string: "client_id=\(self.clientId)&client_secret=\(self.clientSecret)&grant_type=client_credentials"))
        
        let httpClient = HTTPClient(eventLoopGroupProvider: .createNew)
        let response = try await httpClient.execute(request, timeout: .seconds(30))
        let data = try await response.body.collect(upTo: 1024 * 1024)
        
        try await httpClient.shutdown()
        
        // Check the response status for 200 range.
        if !(200...299).contains(response.status.code) {
            throw Abort(HTTPResponseStatus(statusCode: Int(response.status.code)), reason:  String(buffer: data))
        }
        
        // Get the token_type and access_token values
        return try JSONDecoder().decode(Token.self, from: data)
    }
    
    /// Authorize an application client credentials using jwt-bearer grant type returning an OIDC token.
    /// - Parameters:
    ///   - assertion: The  JSON web token assertion to be exchanged.
    /// - Returns: An instance of a ``Token``.
    func jwtBearer(assertion: String) async throws -> Token {
        var request = HTTPClientRequest(url: self.baseURL.absoluteString)
        request.headers.add(name: "content-type", value: "application/x-www-form-urlencoded")
        request.headers.basicAuthorization = BasicAuthorization(username: self.clientId, password: self.clientSecret)
        request.method = HTTPMethod.POST
        request.body = .bytes(ByteBuffer(string: "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&scope=openid&assertion=\(assertion)"))
        
        let httpClient = HTTPClient(eventLoopGroupProvider: .createNew)
        let response = try await httpClient.execute(request, timeout: .seconds(30))
        let data = try await response.body.collect(upTo: 1024 * 1024)
        
        try await httpClient.shutdown()
        
        // Check the response status for 200 range.
        if !(200...299).contains(response.status.code) {
            throw Abort(HTTPResponseStatus(statusCode: Int(response.status.code)), reason:  String(buffer: data))
        }
        
        // Get the token_type and access_token values
        return try JSONDecoder().decode(Token.self, from: data)
    }
    
    /// Authorize an application client credentials using resource owner password credential (ROPC) grant type, returning an OIDC token.
    /// - Parameters:
    ///   - username: The user's username.
    ///   - password: The users' password.
    /// - Returns: An instance of a ``Token``.
    func password(username: String, password: String) async throws -> Token {
        var request = HTTPClientRequest(url: self.baseURL.absoluteString)
        request.headers.add(name: "content-type", value: "application/x-www-form-urlencoded")
        request.method = HTTPMethod.POST
        request.body = .bytes(ByteBuffer(string: "client_id=\(self.clientId)&client_secret=\(self.clientSecret)&grant_type=password&username=\(username)&password=\(password)&scope=openid"))
        
        let httpClient = HTTPClient(eventLoopGroupProvider: .createNew)
        let response = try await httpClient.execute(request, timeout: .seconds(30))
        let data = try await response.body.collect(upTo: 1024 * 1024)
        
        try await httpClient.shutdown()
        
        // Check the response status for 200 range.
        if !(200...299).contains(response.status.code) {
            throw Abort(HTTPResponseStatus(statusCode: Int(response.status.code)), reason:  String(buffer: data))
        }
        
        // Get the token_type and access_token values
        return try JSONDecoder().decode(Token.self, from: data)
    }
    
    /// Generates a JSON web token (JWT) for validating against the token endpoint.
    /// - Parameters:
    ///   - signingSecret: The secret to use to generate a signing key.
    ///   - subject: The subject identifies the principal that is the subject of the JWT.
    ///   - issuer:  The issuer identifies the principal that issued the JWT.
    /// - Returns: A string representing the JWT.
    ///
    ///   The signature is generated using HMAC SHA256.
    func generateJWT(signingSecret: String, subject: String, issuer: String) -> String {
        struct Header: Encodable {
            let alg = "HS256"
            let typ = "JWT"
        }

        struct Payload: Encodable {
            let sub: String
            let iat = Int(UInt64(Date().timeIntervalSince1970))
            let exp = Int(UInt64(Date().advanced(by: 3600).timeIntervalSince1970))
            let iss: String
            let aud: String
            let jti = UUID().uuidString
        }

        let key = SymmetricKey(data: Data(signingSecret.utf8))

        // Create the header.
        let headerJSONData = try! JSONEncoder().encode(Header())
        let headerBase64String = headerJSONData.base64UrlEncodedString(options: .noPaddingCharacters)
        
        // Create the payload.
        let payloadJSONData = try! JSONEncoder().encode(Payload(sub: subject, iss: issuer, aud: self.baseURL.absoluteString))
        let payloadBase64String = payloadJSONData.base64UrlEncodedString(options: .noPaddingCharacters)

        let dataToSign = Data((headerBase64String + "." + payloadBase64String).utf8)
        
        // Generate the signature.
        let signature = HMAC<SHA256>.authenticationCode(for: dataToSign, using: key)
        
        let signatureBase64String = Data(signature).base64UrlEncodedString(options: [.noPaddingCharacters, .safeUrlCharacters])

        // Return the JWT as a string.
        return [headerBase64String, payloadBase64String, signatureBase64String].joined(separator: ".")
    }
}
