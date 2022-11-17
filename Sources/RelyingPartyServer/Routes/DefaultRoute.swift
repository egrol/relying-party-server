//
//  DefaultRoute.swift
//  


import Vapor

/// The default route controller that processes requests to manage user sign-up, registration and sign-in processes.
struct DefaultRoute: RouteCollection {
    private let webAuthnService: WebAuthnService
    private let userService: UserService
    private let authTokenService: TokenService
    private let apiTokenService: TokenService
    
    private let app: Application
    
    /// Initializes the default routes for user interactions.
    /// - Parameters:
    ///   - webapp: Core type representing a Vapor application.
    init(_ webapp: Application) throws {
        // Load the base URL for interacting with the services.
        guard let base = Environment.get("BASE_URL"), let baseURL = URL(string: base) else {
            preconditionFailure("The base URL environment variables not set or invalid.")
        }
        
        guard let relyingPartyId = Environment.get("FIDO2_RELYING_PARTY_ID") else {
            preconditionFailure("The relying party identifier is not set or invalid.")
        }
        
        guard let apiClientId = Environment.get("API_CLIENT_ID"), let apiClientSecret = Environment.get("API_CLIENT_SECRET") else {
            preconditionFailure("FIDO2 related environment variables not set or invalid.")
        }
        
        guard let authClientId = Environment.get("AUTH_CLIENT_ID"), let authClientSecret = Environment.get("AUTH_CLIENT_SECRET") else {
            preconditionFailure("Token related environment variables not set or invalid.")
        }
        
        self.app = webapp
        
        // Create the instances of the Token service for authorization of users and api clients.
        self.authTokenService = TokenService(baseURL: baseURL, clientId: authClientId, clientSecret: authClientSecret)
        self.apiTokenService = TokenService(baseURL: baseURL, clientId: apiClientId, clientSecret: apiClientSecret)
                                             
        // Create the instance of the User service.
        self.userService = UserService(baseURL: baseURL)
        
        // Create the instance of the WebAuthnService service.
        self.webAuthnService = WebAuthnService(baseURL: baseURL, relyingPartyId: relyingPartyId)
    }
    
    func boot(routes: RoutesBuilder) throws {
        let route = routes.grouped("v1")
        // Used for existing accounts with a password resulting in an ROPC to token endpoint.
        route.post("authenticate", use: authenticate)
        
        // Used to initiate a user sign-up, which also requires the OTP validation.
        route.post("signup", use: signup)
        route.post("validate", use: validate)
        
        // Used to generate a FIDO challenge for attestation and assertion.
        route.post("challenge", use: challenge)
        
        // Used to register an authenticatpr with a FIDO attestation result.
        route.post("register", use: register)
        
        // Used to validate an authenticator with a FIDO assertion result.
        route.post("signin", use: signin)
    }
    
    // MARK: User Authentication, Sign-up and Validation
    
    /// The user authentication request.
    /// - Parameters:
    ///   - req: Represents an HTTP request.
    ///
    /// An example JSON request body for authenticating a user:
    /// ```
    /// {
    ///    "email": "john@citizen.com",
    ///    "password": "a1b2c3d4"
    /// }
    /// ```
    func authenticate(_ req: Request) async throws -> Token {
        // Validate the request data.
        try UserAuthentication.validate(content: req)
        let authenticate = try req.content.decode(UserAuthentication.self)
        
        do {
            return try await authTokenService.password(username: authenticate.username, password: authenticate.password)
        }
        catch let error {
            req.logger.error(Logger.Message(stringLiteral: error.localizedDescription))
            throw error
        }
    }
    
    /// The user sign-up request.
    /// - Parameters:
    ///   - req: Represents an HTTP request.
    ///
    /// An example JSON request body for initiating a user sign-up:
    /// ```
    /// {
    ///    "name": "John Citizen",
    ///    "email": "john@citizen.com"
    /// }
    /// ```
    func signup(_ req: Request) async throws -> OTPChallenge {
        // Validate the request data.
        try UserSignUp.validate(content: req)
        let user = try req.content.decode(UserSignUp.self)
        
        do {
            let result = try await userService.generateOTP(token: try await token, email: user.email)
            
            // Calculate the cache expiry in seconds for the OTP transaction.
            let seconds = Int(result.expiry.timeIntervalSinceNow)
            req.logger.info("Caching OTP \(result.transactionId). Set to expire in \(seconds) seconds.")
        
            try await req.cache.set(result.transactionId, to: user, expiresIn: CacheExpirationTime.seconds(seconds))
            
            return OTPChallenge(transactionId: result.transactionId, correlation: result.correlation, expiry: result.expiry)
        }
        catch let error {
            req.logger.error(Logger.Message(stringLiteral: error.localizedDescription))
            throw error
        }
    }
    
    /// Validate the user sign-up request.
    /// - Parameters:
    ///   - req: Represents an HTTP request.
    ///
    /// An example JSON request body for validating an one-time password challenge:
    /// ```
    /// {
    ///    "transactionId": "7705d361-f014-44c1-bae4-2877a0c962b6",
    ///    "otp": "123456"
    /// }
    /// ```
    func validate(_ req: Request) async throws -> Token {
        // Validate the request data.
        try OTPVerification.validate(content: req)
        let validation = try req.content.decode(OTPVerification.self)

        // Make sure the OTP transaction still exists in the cache.
        guard let user = try await req.cache.get(validation.transactionId, as: UserSignUp.self) else {
            req.logger.info("Cached \(validation.transactionId) OTP has expired.")
            throw Abort(.custom(code: 400, reasonPhrase: "One-time password has expired."))
        }
        
        do {
            let result = try await userService.verifyUser(token: try await token, transactionId: validation.transactionId, oneTimePassword: validation.otp, user: user)
            
            // Remove the transaction OTP from cache.
            req.logger.info("Removing \(validation.transactionId) OTP from cache.")
            try? await req.cache.delete(validation.transactionId)
            
            // Generate a JWT representing the userId with the signing secret being the client secret.
            let assertion = self.authTokenService.generateJWT(signingSecret: self.authTokenService.clientSecret, subject: result, issuer: app.addressDescription)
            
            return try await self.authTokenService.jwtBearer(assertion: assertion)
        }
        catch let error {
            req.logger.error(Logger.Message(stringLiteral: error.localizedDescription))
            throw error
        }
    }
    
    // MARK: FIDO2 Device Registration and Verification (sign-in)
    
    /// A request to generate a WebAuthn challenge.
    /// - Parameters:
    ///   - req: Represents an HTTP request.
    ///
    /// An example JSON request body for obtaining a challenge for registration:
    /// ```
    /// {
    ///    "displayName": "John's iPhone",
    ///    "type": "attestation"
    /// }
    /// ```
    ///
    /// The `displayName` is ignored when a assertion challenge is requested.
    ///
    /// Requesting a challenge to complete a subsequent registration operation (attestation) requires the request to have an authorization request header.
    func challenge(_ req: Request) async throws -> FIDO2Challenge {
        // Validate the request data.
        let challenge = try req.content.decode(ChallengeRequest.self)
        
        // Default displayName to nil for assertion requests.
        let displayName: String? = challenge.type == .assertion ? nil : challenge.displayName
        
        // Default to the service token.
        var token = try await token
        
        // If an attestation is request and the bearer doesn't exist in the header, throw error.
        if challenge.type == .attestation, req.headers.bearerAuthorization == nil {
            throw Abort(.unauthorized)
        }
        
        if let bearer = req.headers.bearerAuthorization {
            token = Token(accessToken: bearer.token)
        }
        
        req.logger.info("Request for \(challenge.type) challenge.")
        
        do {
            let result = try await webAuthnService.generateChallenge(token: token, displayName: displayName, type: challenge.type)
            
            return FIDO2Challenge(challenge: result)
        }
        catch let error {
            req.logger.error(Logger.Message(stringLiteral: error.localizedDescription))
            throw error
        }
    }
    
    /// A request to present an attestation object containing a public key to the server for attestation verification and storage.
    /// - Parameters:
    ///   - req: Represents an HTTP request.
    ///
    /// An example JSON request body for registering a FIDO2 device:
    /// ```
    /// {
    ///    "nickname": "John's iPhone",
    ///    "clientDataJSON": "eyUyBg8Li8GH...",
    ///    "attestationObject": "o2M884Yt0a3B7...",
    ///    "credentialId": "VGhpcyBpcyBh..."
    /// }
    func register(_ req: Request) async throws -> HTTPStatus {
        // Check if the bearer header is present, it not throw a 401.
        guard let bearer = req.headers.bearerAuthorization else {
            throw Abort(.unauthorized)
        }
        
        // Create the token.
        let token = Token(accessToken: bearer.token)
        
        // Validate the request data.
        try FIDO2Registration.validate(content: req)
        let registration = try req.content.decode(FIDO2Registration.self)
        
        do {
           try await webAuthnService.createCredentail(token: token, nickname: registration.nickname, clientDataJSON: registration.clientDataJSON, attestationObject: registration.attestationObject, credentialId: registration.credentialId)
        }
        catch let error {
            req.logger.error(Logger.Message(stringLiteral: error.localizedDescription))
            throw error
        }
        
        return HTTPStatus.created
    }
    
    /// A request to present the signed challenge to the server for verification.
    /// - Parameters:
    ///   - req: Represents an HTTP request.
    ///
    /// An example JSON request body for verifing a FIDO2 device:
    /// ```
    /// {
    ///    "clientDataJSON": "eyUyBg8Li8GH...",
    ///    "authenticatorData": "o2M884Yt0a3B7...",
    ///    "credentialId": "VGhpcyBpcyBh...",
    ///    "signature": "OP84jBpcyB...
    /// }
    func signin(_ req: Request) async throws -> Token {
        // Validate the request data.
        try FIDO2Verification.validate(content: req)
        let verification = try req.content.decode(FIDO2Verification.self)
        
        do {
            let result = try await webAuthnService.verifyCredentail(token: try await token, clientDataJSON: verification.clientDataJSON, authenticatorData: verification.authenticatorData, credentialId: verification.credentialId, signature: verification.signature)
            
            
            print(String(decoding: result, as: UTF8.self))
            
            // Parse out the assertion
            guard let json = try JSONSerialization.jsonObject(with: result, options: []) as? [String: Any], let assertion = json["assertion"] as? String else {
                throw Abort(.custom(code: 1, reasonPhrase: "Unable to parse the assertion data from the FIDO2 assertion response."))
            }
            
            // Return an access token based on the JWT assertion.
            return try await authTokenService.jwtBearer(assertion: assertion)
        }
        catch let error {
            req.logger.error(Logger.Message(stringLiteral: error.localizedDescription))
            throw error
        }
    }
    
    // MARK: Admin
    
    /// The ``Token`` for authorizing requests to back-end services.
    var token: Token {
        get async throws {
            // Get token from cache
            if let value = try await app.cache.get("token", as: Token.self) {
                app.logger.info("Cached token \(value.accessToken).")
                return value
            }
            
            // Obtain a new token.
            let value = try await self.apiTokenService.clientCredentials()
            
            // Add to cache but will expiry the token (in cache) 60 before it's actual expiry.
            try await app.cache.set("token", to: value, expiresIn: CacheExpirationTime.seconds(value.expiry - 60))
            app.logger.info("Caching token \(value.accessToken). Set to expire in \(value.expiry - 60) seconds.")
            return value
        }
    }
}
