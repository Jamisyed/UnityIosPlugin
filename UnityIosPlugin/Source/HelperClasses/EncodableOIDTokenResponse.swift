//
//  File.swift
//  UnityIosPlugin
//
//  Created by Syed Abdul Rehman Jami on 22/09/2023.
//

import Foundation
import UIKit
import AppAuth
import SafariServices
import AuthenticationServices

// Define your wrapper object conforming to Encodable
struct EncodableOIDTokenResponse: Encodable {
    let accessToken: String?
    let tokenType: String?
    let refreshToken: String?
    let idToken: String?
    let scope: String?
    let additionalParameters: [String: String]?
    let tokenExpirationDate: Date?
    
    enum CodingKeys: String, CodingKey {
        case accessToken
        case tokenType
        case refreshToken
        case idToken
        case scope
        case additionalParameters
        case tokenExpirationDate
    }
    
    init(_ tokenResponse: OIDTokenResponse) {
        self.accessToken = tokenResponse.accessToken
        self.tokenType = tokenResponse.tokenType
        self.refreshToken = tokenResponse.refreshToken
        self.idToken = tokenResponse.idToken
        self.scope = tokenResponse.scope
        self.additionalParameters = EncodableOIDTokenResponse.convertParametersToStrings(tokenResponse.additionalParameters)
        self.tokenExpirationDate = tokenResponse.accessTokenExpirationDate
    }
    
    static func convertParametersToStrings(_ parameters: [String: NSCopying & NSObjectProtocol]?) -> [String: String]? {
        guard let parameters = parameters else {
            return nil
        }
        
        var convertedParameters: [String: String] = [:]
        for (key, value) in parameters {
            if let stringValue = value.copy(with: nil) as? String {
                convertedParameters[key] = stringValue
            }
        }
        
        return convertedParameters
    }
}
