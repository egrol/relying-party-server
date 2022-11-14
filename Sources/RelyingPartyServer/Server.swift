//
//  Server.swift
//  

import Vapor

@main
struct RelyingPartyServer {
    public static func main() async throws {
        var env = try Environment.detect()
        try LoggingSystem.bootstrap(from: &env)

        let webapp = Application(env)
        defer {
            webapp.shutdown()
        }
        
        // MARK: Configure Sessions
        webapp.sessions.use(.memory)
        webapp.middleware.use(SessionsMiddleware(session: MemorySessions(storage: .init())))
        
        // MARK: Configure Cache
        webapp.caches.use(.memory)
        
        // MARK: Configure Routes
        try webapp.register(collection: WellKnownRoute())
        try webapp.register(collection: DefaultRoute(webapp))
        
        try webapp.run()
    }
}
