//
//  WellKnownRoute.swift
//  

import Vapor

/// The route controller for the `.well-known` endpoint.
struct WellKnownRoute: RouteCollection {
    func boot(routes: Vapor.RoutesBuilder) throws {
        let route = routes.grouped(WellKnownMiddleware())
        route.get(".well-known", ":filename") { req -> String in
            // Ensure the parameter is provided.
            guard let filename = req.parameters.get("filename") else {
                throw Abort(.badRequest)
            }
            
            let directory = DirectoryConfiguration.detect()
            
            // Check if the file exists, otherwise throw a 404.
            guard let contents = try? String(contentsOfFile: "\(directory.publicDirectory)\(filename)") else {
                throw Abort(.notFound)
            }
            
            // Return the content of the file, the WellKnownMiddleware will include the 'application/json' header.
            return contents
        }
    }
}
