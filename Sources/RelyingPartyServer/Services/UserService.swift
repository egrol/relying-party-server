//
//  UserService.swift
//  

import Vapor
import AsyncHTTPClient

/// The `UserService` for issuing and validating one-time passwords and creating a new user.
class UserService {
    /// The base ``URL`` for the host.
    let baseURL: URL
    
    /// Initialize the user service.
    /// - Parameters:
    ///   - baseURL: The base ``URL`` for the host.
    init(baseURL: URL) {
        self.baseURL = baseURL.appendingPathComponent("/v2.0")
    }
    
    /// Generate an one-time password to be emailed.
    /// - Parameters:
    ///   - token: The ``Token`` for authorizing requests to back-end services.
    ///   - email: The user's email address
    func generateOTP(token: Token, email: String) async throws -> (transactionId: String, correlation: String, expiry: Date) {
        var request = HTTPClientRequest(url: self.baseURL.absoluteString + "/factors/emailotp/transient/verifications")
        request.headers.add(name: "content-type", value: "application/json")
        request.headers.add(name: "accept", value: "application/json")
        request.headers.bearerAuthorization = BearerAuthorization(token: token.accessToken)
        request.method = HTTPMethod.POST
        request.body = .bytes(ByteBuffer(string: """
            {
                "emailAddress": "\(email)"
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
        
        // Parse the data retrieving the transactionId
        if let json = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any], let transactionId = json["id"] as? String, let correlation = json["correlation"] as? String, let utcDate = json["expiry"] as? String, let expiry = DateFormatter.iso8061FormatterBehavior.date(from: utcDate) {
            
            return (transactionId: transactionId, correlation: correlation, expiry: expiry)
        }
        
        throw Abort(.badRequest)
    }
    
    
    /// Verify a one-time password associated with the user sign-up operation.
    /// - Parameters:
    ///   - token: The ``Token`` for authorizing requests to back-end services.
    ///   - transactionId: The specific verification identifier.
    ///   - oneTimePassword: The one-time password value
    ///   - user: The use's sign-up details.
    func verifyUser(token: Token, transactionId: String, oneTimePassword: String, user: UserSignUp) async throws -> String {
        var request = HTTPClientRequest(url: self.baseURL.absoluteString + "/factors/emailotp/transient/verifications/\(transactionId)")
        request.headers.add(name: "content-type", value: "application/json")
        request.headers.add(name: "accept", value: "application/json")
        request.headers.bearerAuthorization = BearerAuthorization(token: token.accessToken)
        request.method = HTTPMethod.POST
        request.body = .bytes(ByteBuffer(string: """
            {
                "otp": "\(oneTimePassword)"
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
        
        // Create the user.
        return try await createUser(token: token, email: user.email, name: user.name)
    }
    
    /// Create a new user in IBM Security Verify.
    /// - Parameters:
    ///   - token: The ``Token`` for authorizing requests to back-end services.
    ///   - email: The user's email address.
    ///   - name: The users' first and last name.
    private func createUser(token: Token, email: String, name: String) async throws -> String {
        var request = HTTPClientRequest(url: self.baseURL.absoluteString + "/Users")
        request.headers.add(name: "content-type", value: "application/scim+json")
        request.headers.add(name: "accept", value: "application/scim+json")
        request.headers.bearerAuthorization = BearerAuthorization(token: token.accessToken)
        request.method = HTTPMethod.POST
        request.body = .bytes(ByteBuffer(string: """
            {
               "userName": "\(email)",
               "name": {
                  "givenName": "\(name)"
               },
               "urn:ietf:params:scim:schemas:extension:ibm:2.0:Notification": {
                  "notifyType": "EMAIL",
                  "notifyPassword": false
               },
               "urn:ietf:params:scim:schemas:extension:ibm:2.0:User": {
                  "realm": "cloudIdentityRealm",
                  "userCategory": "regular",
                  "twoFactorAuthentication": false
               },
               "active": true,
               "emails": [{
                    "type": "work",
                    "value": "\(email)"
               }],
               "schemas": [
                  "urn:ietf:params:scim:schemas:extension:ibm:2.0:Notification",
                  "urn:ietf:params:scim:schemas:extension:ibm:2.0:User",
                  "urn:ietf:params:scim:schemas:core:2.0:User"
               ]
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
        
        // Get owner id.
        guard let json = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any], let userId = json["id"] as? String else {
            throw Abort(.custom(code: 1, reasonPhrase: "Unable to parse user identifer."))
        }
        
        return userId
    }
}
