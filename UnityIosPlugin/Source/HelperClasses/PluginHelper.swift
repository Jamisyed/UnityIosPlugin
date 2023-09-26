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


protocol PluginHelperDelegate{
    func didChange(_ state: OIDAuthState)
    func authState(_ state: OIDAuthState, didEncounterAuthorizationError error: Error)
}

class PluginHelper: NSObject {
    
    
    var authState: OIDAuthState?
    var pluginHelperDelegate: PluginHelperDelegate?
    var vc: UIViewController?
  
    func setAuthState(authState: OIDAuthState?){
        self.authState = authState
        self.authState?.stateChangeDelegate = self
    }
    func openWebURL(url: URL, completeion : @escaping ASWebAuthenticationSession.CompletionHandler){
        
        
        let redirectScheme = "com.terravirtua.example"
        let authenticationVC = ASWebAuthenticationSession(url: url, callbackURLScheme: redirectScheme,completionHandler: completeion)
        //        let authenticationVC = ASWebAuthenticationSession(url: URL(string: "https://dashboard.bimtvist.com")!, callbackURLScheme: redirectScheme) { callbackURL, error in
        //            if let error = error {
        //                let safariError = OIDErrorUtilities.error(with: .userCanceledAuthorizationFlow, underlyingError: error, description: "User cancelled.")
        //                print(safariError)
        //
        //                //                if error.localizedDescription.unicodeScalars == ASWebAuthenticationSessionError.canceledLogin.rawValue {
        //                //                    // User canceled the authentication
        //                //                    print("Authentication canceled by the user")
        //                //                } else {
        //                //                    // Handle other errors
        //                //                    print("Authentication error: \(error.localizedDescription)")
        //                //                }
        //            } else {
        //                // Authentication succeeded, callbackURL contains the result
        //                print("Authentication succeeded. Callback URL: \(callbackURL)")
        //            }
        //        }
        authenticationVC.presentationContextProvider = self
        authenticationVC.prefersEphemeralWebBrowserSession = false
        
        authenticationVC.start()
    }
    
}
extension PluginHelper: ASWebAuthenticationPresentationContextProviding{
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        let vc = UIApplication.shared.delegate?.window??.rootViewController
        return (vc?.view.window ?? ASPresentationAnchor())
    }
}

extension PluginHelper:OIDAuthStateChangeDelegate, OIDAuthStateErrorDelegate{
    func didChange(_ state: OIDAuthState) {
        pluginHelperDelegate?.didChange(state)
    }
    func authState(_ state: OIDAuthState, didEncounterAuthorizationError error: Error) {
        //  self.logMessage("Received authorization error: \(error)")
        pluginHelperDelegate?.authState(state, didEncounterAuthorizationError: error)
    }
}


