//
//  WellKnownMiddleware.swift
//  

import Vapor

/// Ensures the response header content type is `application/json` for requests to the `.well-known` endpoint.
struct WellKnownMiddleware: Middleware {
    func respond(to request: Request, chainingTo next: Responder) -> EventLoopFuture<Response> {
        return next.respond(to: request).map { response in
            response.headers.add(name: "content-type", value: "application/json")
            return response
        }
    }
}
