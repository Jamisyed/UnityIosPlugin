//  UnityPlugin.swift
//  UnityIosPlugin
//  Created by Syed Abdul Rehman Jami on 02/06/2023.



import Foundation
import UIKit
import AppAuth
import SafariServices
import AuthenticationServices

typealias PostRegistrationCallback = (_ configuration: OIDServiceConfiguration?, _ registrationResponse: OIDRegistrationResponse?) -> Void


@objcMembers
@objc public class UnityPlugin: NSObject {
    
    
    public weak var viewController: UIViewController?
    
    
    private var kIssuer: String?//= "https://accounts.c.com/realms/virtua"
    private var kClientID: String?// = "MobileApp"
    private var kRedirectURI: String? //= "com.example.v3:/oauth2redirect"
    
    private var kAppAuthExampleAuthStateKey: String = "authState";
    
    var currentAuthorizationFlow: OIDExternalUserAgentSession?
    
    
    var authState: OIDAuthState?
    var pluginHelper: PluginHelper?
    
    //   var completionSafari: ((Bool) -> ())?
    
    static let shared = UnityPlugin()
    
    private override init() {
        super.init()
        self.pluginHelper = PluginHelper()
        self.pluginHelper?.pluginHelperDelegate = self
        
    }
    
    
    private func configure(issuer: String, clientID: String, redirectURI: String) -> String {
        // Validate issuer URL
        
        var receivedString = issuer.components(separatedBy: ",")
        
        guard receivedString.count == 3 else {
            return "Invalid values format"
        }
        
        
        let issuer = receivedString[0]
        let clientID = receivedString[1]
        let redirectURI = receivedString[2]
        
        
        guard let issuerURL = URL(string: issuer ) else {
            return "Invalid issuer URL"
        }
        
        // Validate client ID
        guard !clientID.isEmpty else {
            return "Invalid client ID"
        }
        
        // Validate redirect URI
        guard !redirectURI.isEmpty else {
            return "Invalid redirect URI"
        }
        
        
        // All validations passed, update the credentials
        self.kIssuer = issuer
        self.kClientID = clientID
        self.kRedirectURI = redirectURI
        
        
        
        return "Success: \(String(describing: kIssuer!)),\(String(describing: kClientID!)),\(String(describing: kRedirectURI!))"
    }
    
    
    
    
    
    private func _openUrl(url: String) -> String{
        guard let url = URL(string: url) else { return "URL is not valid " + "URL is: " + url }
        self.pluginHelper?.openWebURL(url: url){ callbackURL, error in
            if let error = error {
                let safariError = OIDErrorUtilities.error(with: .userCanceledAuthorizationFlow, underlyingError: error, description: "User cancelled.")
                print(safariError)
                
                //                if error.localizedDescription.unicodeScalars == ASWebAuthenticationSessionError.canceledLogin.rawValue {
                //                    // User canceled the authentication
                //                    print("Authentication canceled by the user")
                //                } else {
                //                    // Handle other errors
                //                    print("Authentication error: \(error.localizedDescription)")
                //                }
            } else {
                // Authentication succeeded, callbackURL contains the result
                print("Authentication succeeded. Callback URL: \(String(describing: callbackURL))")
            }
        }
        
        return  "URL is valid " + "URL is: " + url.absoluteString
    }
    
    
    
    
    private func _logout(completion: @escaping ((Bool,String)-> Void)) {
        // Your logout implementation here
        
        if self.loadState(){
            if self.authState != nil{
                let idToken = self.authState?.lastTokenResponse?.idToken  ?? ""
                
                
                
                let request = OIDEndSessionRequest(configuration:authState!.lastAuthorizationResponse.request.configuration,
                                                   idTokenHint: idToken,
                                                   postLogoutRedirectURL: URL(string:kRedirectURI ?? "")!,
                                                   additionalParameters: nil)
                
                
                guard let agent = OIDExternalUserAgentIOS(presenting: viewController!,prefersEphemeralSession: true) else {
                    completion(false,"Agent Initialize failed")
                    return
                }
                
                
                //            guard let appDelegate = UIApplication.shared.delegate as? AppDelegate else {
                //                self.logMessage("Error accessing AppDelegate")
                //                return
                //            }
                
                
                self.currentAuthorizationFlow = OIDAuthorizationService.present(request, externalUserAgent: agent,
                                                                                callback: { (response, error) in
                    if let response = response {
                        //delete cookies just in case
                        HTTPCookieStorage.shared.cookies?.forEach { cookie in
                            HTTPCookieStorage.shared.deleteCookie(cookie)
                        }
                        completion(true,"")
                        // successfully logout
                    }
                    if let err = error {
                        // print Error
                        print("")
                        completion(true,"")
                    }
                })
            }else {
                completion(false,"State nil found")
            }
        }else{
            completion(false,"State nil found")
        }
        
        
    }
    
    private func authenticateWithAutoCodeExchange(completion: @escaping (Bool,String,String,String) -> Void)  {
        
        guard let issuer = URL(string: kIssuer ?? "") else {
            self.logMessage("Error creating URL for : \(String(describing: kIssuer))")
            completion(false,"","","Error creating URL for : \(String(describing: kIssuer))")
            return
        }
        
        self.logMessage("Fetching configuration for issuer: \(issuer)")
        
        // discovers endpoints
        OIDAuthorizationService.discoverConfiguration(forIssuer: issuer) { configuration, error in
            
            guard let config = configuration else {
                self.logMessage("Error retrieving discovery document: \(error?.localizedDescription ?? "DEFAULT_ERROR")")
                self.setAuthState(nil)
                completion(false,"","","Error retrieving discovery document: \(error?.localizedDescription ?? "DEFAULT_ERROR")")
                return
            }
            
            self.logMessage("Got configuration: \(config)")
            
            if let clientId = self.kClientID {
                self.doAuthWithAutoCodeExchange(configuration: config, clientID: clientId, clientSecret: nil){ authState in
                    let lastTokenResponse =  self.getLastTokenResponse()
                    let accessToken = self.getAccessToken()
                    completion(true,accessToken,lastTokenResponse,"")
                }
            } else {
                self.doClientRegistration(configuration: config) { configuration, response in
                    
                    guard let configuration = configuration, let clientID = response?.clientID else {
                        self.logMessage("Error retrieving configuration OR clientID")
                        return
                    }
                    
                    self.doAuthWithAutoCodeExchange(configuration: configuration,
                                                    clientID: clientID,
                                                    clientSecret: response?.clientSecret){ authState in
                        let lastTokenResponse =  self.getLastTokenResponse()
                        let accessToken = self.getAccessToken()
                        completion(true,accessToken,lastTokenResponse,"")
                        
                    }
                }
            }
        }
        
    }
    private func doAuthWithAutoCodeExchange(configuration: OIDServiceConfiguration, clientID: String, clientSecret: String?, completion: @escaping (OIDAuthState) -> Void ) {
        
        guard let redirectURI = URL(string: kRedirectURI ?? "") else {
            self.logMessage("Error creating URL for : \(String(describing: kRedirectURI))")
            return
        }
        
        //        guard let appDelegate = UIApplication.shared.delegate as? AppDelegate else {
        //            self.logMessage("Error accessing AppDelegate")
        //            return
        //        }
        
        // builds authentication request
        let request = OIDAuthorizationRequest(configuration: configuration,
                                              clientId: clientID,
                                              clientSecret: clientSecret,
                                              scopes: [OIDScopeOpenID, OIDScopeProfile],
                                              redirectURL: redirectURI,
                                              responseType: OIDResponseTypeCode,
                                              additionalParameters: nil)
        
        // performs authentication request
        logMessage("Initiating authorization request with scope: \(request.scope ?? "DEFAULT_SCOPE")")
        
        self.currentAuthorizationFlow = OIDAuthState.authState(byPresenting: request, presenting: viewController!) { authState, error in
            
            if let authState = authState {
                self.setAuthState(authState)
                self.logMessage("Got authorization tokens. Access token: \(authState.lastTokenResponse?.accessToken ?? "DEFAULT_TOKEN")")
                
                
                
                completion(authState)
                
                
                
            } else {
                self.logMessage("Authorization error: \(error?.localizedDescription ?? "DEFAULT_ERROR")")
                self.setAuthState(nil)
            }
        }
    }
    private func doClientRegistration(configuration: OIDServiceConfiguration, callback: @escaping PostRegistrationCallback) {
        
        guard let redirectURI = URL(string: kRedirectURI ?? "") else {
            self.logMessage("Error creating URL for : \(kRedirectURI)")
            return
        }
        
        let request: OIDRegistrationRequest = OIDRegistrationRequest(configuration: configuration,
                                                                     redirectURIs: [redirectURI],
                                                                     responseTypes: nil,
                                                                     grantTypes: nil,
                                                                     subjectType: nil,
                                                                     tokenEndpointAuthMethod: "client_secret_post",
                                                                     additionalParameters: nil)
        
        // performs registration request
        self.logMessage("Initiating registration request")
        
        OIDAuthorizationService.perform(request) { response, error in
            
            if let regResponse = response {
                self.setAuthState(OIDAuthState(registrationResponse: regResponse))
                self.logMessage("Got registration response: \(regResponse)")
                callback(configuration, regResponse)
            } else {
                self.logMessage("Registration error: \(error?.localizedDescription ?? "DEFAULT_ERROR")")
                self.setAuthState(nil)
            }
        }
    }
    
    // MARK: Helper Methods
    
    private func setAuthState(_ authState: OIDAuthState?) {
        if (self.authState == authState) {
            return;
        }
        self.authState = authState;
        self.pluginHelper?.setAuthState(authState: authState)
        self.stateChanged()
    }
    
    private func logMessage(_ message: String) {
        // Log message implementation
    }
   
    
    
    func doAuthWithoutCodeExchange(configuration: OIDServiceConfiguration, clientID: String, clientSecret: String?) {
        
        guard let redirectURI = URL(string: kRedirectURI ?? "") else {
            self.logMessage("Error creating URL for : \(String(describing: kRedirectURI))")
            return
        }
        
        //        guard let appDelegate = UIApplication.shared.delegate as? AppDelegate else {
        //            self.logMessage("Error accessing AppDelegate")
        //            return
        //        }
        
        // builds authentication request
        let request = OIDAuthorizationRequest(configuration: configuration,
                                              clientId: clientID,
                                              clientSecret: clientSecret,
                                              scopes: [OIDScopeOpenID, OIDScopeProfile],
                                              redirectURL: redirectURI,
                                              responseType: OIDResponseTypeCode,
                                              additionalParameters: nil)
        
        // performs authentication request
        logMessage("Initiating authorization request with scope: \(request.scope ?? "DEFAULT_SCOPE")")
        
        self.currentAuthorizationFlow = OIDAuthorizationService.present(request, presenting: viewController!) { (response, error) in
            
            if let response = response {
                let authState = OIDAuthState(authorizationResponse: response)
                self.setAuthState(authState)
                self.logMessage("Authorization response with code: \(response.authorizationCode ?? "DEFAULT_CODE")")
                // could just call [self tokenExchange:nil] directly, but will let the user initiate it.
            } else {
                self.logMessage("Authorization error: \(error?.localizedDescription ?? "DEFAULT_ERROR")")
            }
        }
    }
    
    
    
    func userInfo(completion: @escaping ((Bool,String,String)-> Void)){
        guard let userinfoEndpoint = self.authState?.lastAuthorizationResponse.request.configuration.discoveryDocument?.userinfoEndpoint else {
            self.logMessage("Userinfo endpoint not declared in discovery document")
            completion(false,"","Userinfo endpoint not declared in discovery document")
            return
        }
        
        self.logMessage("Performing userinfo request")
        
        let currentAccessToken: String? = self.authState?.lastTokenResponse?.accessToken
        
        self.authState?.performAction() { (accessToken, idToken, error) in
            
            if error != nil  {
                self.logMessage("Error fetching fresh tokens: \(error?.localizedDescription ?? "ERROR")")
                completion(false,"","Error fetching fresh tokens: \(error?.localizedDescription ?? "ERROR")")
                return
            }
            
            guard let accessToken = accessToken else {
                self.logMessage("Error getting accessToken")
                completion(false,"","Error getting accessToken")
                return
            }
            
            if currentAccessToken != accessToken {
                self.logMessage("Access token was refreshed automatically (\(currentAccessToken ?? "CURRENT_ACCESS_TOKEN") to \(accessToken))")
            } else {
                self.logMessage("Access token was fresh and not updated \(accessToken)")
            }
            
            var urlRequest = URLRequest(url: userinfoEndpoint)
            urlRequest.allHTTPHeaderFields = ["Authorization":"Bearer \(accessToken)"]
            
            let task = URLSession.shared.dataTask(with: urlRequest) { data, response, error in
                
                DispatchQueue.main.async {
                    
                    guard error == nil else {
                        self.logMessage("HTTP request failed \(error?.localizedDescription ?? "ERROR")")
                        completion(false,"","HTTP request failed \(error?.localizedDescription ?? "ERROR")")
                        return
                    }
                    
                    guard let response = response as? HTTPURLResponse else {
                        self.logMessage("Non-HTTP response")
                        completion(false,"","Non-HTTP response")
                        return
                    }
                    
                    guard let data = data else {
                        self.logMessage("HTTP response data is empty")
                        completion(false,"","HTTP response data is empty")
                        return
                    }
                    
                    var json: [String: Any]?
                    
                    do {
                        json = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any]
                    } catch {
                        self.logMessage("JSON Serialization Error")
                        completion(false,"","JSON Serialization Error")
                    }
                    
                    if response.statusCode != 200 {
                        // server replied with an error
                        let responseText: String? = String(data: data, encoding: String.Encoding.utf8)
                        
                        if response.statusCode == 401 {
                            // "401 Unauthorized" generally indicates there is an issue with the authorization
                            // grant. Puts OIDAuthState into an error state.
                            let oauthError = OIDErrorUtilities.resourceServerAuthorizationError(withCode: 0,
                                                                                                errorResponse: json,
                                                                                                underlyingError: error)
                            self.authState?.update(withAuthorizationError: oauthError)
                            self.logMessage("Authorization Error (\(oauthError)). Response: \(responseText ?? "RESPONSE_TEXT")")
                            completion(false,"","Authorization Error (\(oauthError)). Response: \(responseText ?? "RESPONSE_TEXT")")
                        } else {
                            self.logMessage("HTTP: \(response.statusCode), Response: \(responseText ?? "RESPONSE_TEXT")")
                            completion(false,"","HTTP: \(response.statusCode), Response: \(responseText ?? "RESPONSE_TEXT")")
                        }
                        completion(false,"","Something went wrong")
                        return
                    }
                    
                    if let json = json {
                        
                        
                        do {
                            let jsonData = try JSONSerialization.data(withJSONObject: json, options: [])
                            if let jsonString = String(data: jsonData, encoding: .utf8) {
                                completion(true,jsonString,"")
                            }
                        } catch {
                            print("Error converting dictionary to JSON: \(error)")
                            completion(false,"","Error converting dictionary to JSON: \(error)")
                        }
                    }
                }
            }
            
            task.resume()
        }
    }
    
    
    
    func _refreshTokenRequest(completion: @escaping ((Bool,String,String,String)-> Void)){
        
        
        self.logMessage("Performing userinfo request")
        
        let currentAccessToken: String? = self.authState?.lastTokenResponse?.accessToken
        
        self.authState?.performAction() { (accessToken, idToken, error) in
            
            if error != nil  {
                self.logMessage("Error fetching fresh tokens: \(error?.localizedDescription ?? "ERROR")")
                completion(false,"","","Error fetching fresh tokens: \(error?.localizedDescription ?? "ERROR")")
                return
            }
            
            guard let accessToken = accessToken else {
                self.logMessage("Error getting accessToken")
                completion(false,"","","Error getting accessToken")
                return
            }
            
            if currentAccessToken != accessToken {
                self.logMessage("Access token was refreshed automatically (\(currentAccessToken ?? "CURRENT_ACCESS_TOKEN") to \(accessToken))")
            } else {
                self.logMessage("Access token was fresh and not updated \(accessToken)")
            }
            
            completion(true,accessToken, self.getLastTokenResponse(),"")
        }
    }
}


extension UnityPlugin {
    
    func saveState() {
        
        var data: Data? = nil
        
        if let authState = self.authState {
            data = NSKeyedArchiver.archivedData(withRootObject: authState)
        }
        
        if let userDefaults = UserDefaults(suiteName: "com.terravirtua.prod.unity") {
            userDefaults.set(data, forKey: kAppAuthExampleAuthStateKey)
            userDefaults.synchronize()
        }
    }
    
    func loadState() -> Bool {
        guard let data = UserDefaults(suiteName: "com.terravirtua.prod.unity")?.object(forKey: kAppAuthExampleAuthStateKey) as? Data else {
            return false
        }
        
        if let authState = NSKeyedUnarchiver.unarchiveObject(with: data) as? OIDAuthState {
            self.setAuthState(authState)
            return true
        }
        return false
    }
    
    
    func stateChanged() {
        self.saveState()
        
    }
    
 
    
}


//MARK: OIDAuthState Delegate
extension UnityPlugin:  PluginHelperDelegate {
    
    func didChange(_ state: OIDAuthState) {
        self.stateChanged()
    }
    
    func authState(_ state: OIDAuthState, didEncounterAuthorizationError error: Error) {
        self.logMessage("Received authorization error: \(error)")
    }
}





// Add this extension to make the class compatible with Objective-C
extension UnityPlugin {
    
    // Add `sharedInstance` property to access the singleton instance in Objective-C
    @objc public static let sharedInstance = UnityPlugin.shared
    
    // Add `configureWithIssuer:clientID:redirectURI:` method to configure the instance
    @objc public func configure(withIssuer issuer: NSString, clientID: NSString, redirectURI: NSString) -> String {
        // self.showAlertWithMessage()
        return  self.configure(issuer: issuer as String, clientID: clientID as String, redirectURI: redirectURI as String)
    }
    
    @objc public func getAccessToken() -> String {
        guard loadState(),
              let accessToken = authState?.lastTokenResponse?.accessToken
        else {
            return ""
        }
        
        return accessToken
    }
    
    @objc public func getAccessTokenExpiryDateAsString() -> String{
        if self.loadState(){
            
            let currentDate =  self.authState?.lastTokenResponse?.accessTokenExpirationDate ?? Date()// Get the current date
            
            let dateFormatter = DateFormatter() // Create a date formatter
            dateFormatter.dateFormat = "yyyy-MM-dd HH:mm:ss a"  // Set the desired date format
            
            let dateString = dateFormatter.string(from: currentDate) // Convert the date to a string
            
            print(dateString) // Output the date string
            return dateString
        }
        return ""
    }
    @objc public func getAccessTokenExpiryInSeconds() -> Int{
        guard loadState(),
              let expirationDate = authState?.lastTokenResponse?.accessTokenExpirationDate
        else {
            return 0
        }
        
        return CalculateExpiryTimeInMinutes(date: expirationDate)
    }
    @objc public func isAccessTokenExpired() -> Bool{
        let accessTokenExpiry =  getAccessTokenExpiryInSeconds()
        return accessTokenExpiry > 0 ? false : true
    }
    
    
    
    @objc public func getRefreshToken() -> String{
        
        if self.loadState(){
            return self.authState?.lastTokenResponse?.refreshToken ?? ""
        }
        return ""
    }
    
    @objc public func getRefreshTokenExpiryInSeconds() -> Int{
        
        guard loadState(),
              let refreshTokenExpiry = authState?.lastTokenResponse?.additionalParameters?["refresh_expires_in"] as? Int
        else {
            return 0
        }
        
        return refreshTokenExpiry
    }
    @objc public func isRefreshTokenExpired() -> Bool{
        let refreshTokenExpiry =  self.getRefreshTokenExpiryInSeconds()
        return refreshTokenExpiry > 0 ? false : true
    }
    
    @objc public func getLastTokenResponse() -> String{
        guard loadState(),
              let lastTokenResponse = authState?.lastTokenResponse,
              let jsonString = encodeToJsonString(EncodableOIDTokenResponse(lastTokenResponse))
        else {
            return ""
        }
        
        return jsonString
    }
    @objc public func getUserInfo(completion: @escaping ((Bool,String,String)-> Void)){
        self.userInfo(completion: completion)
    }
    @objc public func refreshTokenRequest(completion: @escaping ((Bool,String,String,String)-> Void)){
        self._refreshTokenRequest(completion: completion)
    }
    // Add `authenticateWithAutoCodeExchangeWithCompletion:` method for Objective-C
    @objc public func login(completionHandler: @escaping (Bool,String,String,String) -> Void) {
        self.authenticateWithAutoCodeExchange(completion: completionHandler)
    }
    
    // Add `logout` method for Objective-C
    @objc public func logout(completion: @escaping ((Bool,String)-> Void)) {
        self._logout(completion: completion)
    }
    
    // Method to receive the UIViewController reference from Unity
    @objc public func passViewController(_ vc: UIViewController) {
        // Convert the pointer to a UIViewController reference
        
        self.viewController  = vc
        // self.showAlertWithMessage()
        
    }
    @objc public func openUrl(url: String) -> String{
        self._openUrl(url: url)
    }
}


extension UnityPlugin{
    func showAlertWithMessage() {
        let alertController = UIAlertController(title: "Success", message: "We have successfully passed the ViewController", preferredStyle: .alert)
        
        let okAction = UIAlertAction(title: "OK", style: .default) { _ in
            // Handle OK button tap action
        }
        
        alertController.addAction(okAction)
        
        // Present the alert view controller
        
        self.viewController?.present(alertController, animated: true, completion: nil)
        
    }
    
    func CalculateExpiryTimeInMinutes(date fromServer: Date) -> Int{
        // Get the current date and time
        let currentDate = Date()
        
        // Get the expiry date from the server (replace with your actual code to get the expiry date object)
        let expiryDate = fromServer
        
        
        // Get the current calendar
        let calendar = Calendar.current
        
        // Calculate the difference between the current date and the expiry date
        let components = calendar.dateComponents([.second], from: currentDate, to: expiryDate)
        
        // Get the remaining minutes
        if let remainingMinutes = components.second {
            if remainingMinutes > 0 {
                
                print("Token expires in \(remainingMinutes) seconds.")
                return remainingMinutes
                // return ("Token expires in \(remainingMinutes) minutes.")
            } else {
                
                print("Token has expired.")
                return remainingMinutes
                //  return ("Token has expired.")
            }
        }
        return 0
    }
    
    // Method to encode custom object to JSON string
    func encodeToJsonString<T: Encodable>(_ object: T) -> String? {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted
        
        do {
            let jsonData = try encoder.encode(object)
            return String(data: jsonData, encoding: .utf8)
        } catch {
            print("Error encoding object to JSON: \(error)")
            return nil
        }
    }
    
    
}













