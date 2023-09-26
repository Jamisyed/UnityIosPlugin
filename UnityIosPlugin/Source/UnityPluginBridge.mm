
//  UnityPluginBridge.m
//  UnityIosPlugin
//  Created by Syed Abdul Rehman Jami on 02/06/2023.


#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#ifdef __OBJC__
#if __has_include(<UnityIosPlugin/UnityIosPlugin-Swift.h>)
#import <UnityIosPlugin/UnityIosPlugin-Swift.h>
#endif
#endif

#ifdef __OBJC__
#if __has_include(<UnityFramework/UnityFramework-Swift.h>)
#import "UnityFramework/UnityFramework-Swift.h"
#endif
#endif



extern "C" {

#pragma mark - Functions


void instantiateViewController(){
    
    
    UIWindow *mainWindow = [UIApplication sharedApplication].delegate.window;
    // Access the root view controller
    UIViewController *rootViewController = mainWindow.rootViewController;
    [[UnityPlugin sharedInstance] passViewController:rootViewController];
}

const char* openURL(char* url){
    NSString* webURL = [NSString stringWithUTF8String:url];
    NSString* result = [[UnityPlugin sharedInstance] openUrlWithUrl:webURL];
    // Convert the resulting configuration NSString to a C-style string and return it
    return [result UTF8String];
}

const char* configureAppAuthManager(char* issuer, const char* clientID, const char* redirectURI){
    // Convert C-style strings to NSString
    NSString* Kissuer = [NSString stringWithUTF8String:issuer];
    NSString* KclientID = [NSString stringWithUTF8String:clientID];
    NSString* KredirectURI = [NSString stringWithUTF8String:redirectURI];
    
    // Your implementation for the configureAppAuthManager method
    UIWindow *mainWindow = [UIApplication sharedApplication].delegate.window;
    
    // Access the root view controller
    UIViewController *rootViewController = mainWindow.rootViewController;
    
    
    if (rootViewController) {
        // Root view controller exists
        NSLog(@"Root view controller is not nil");
        
        [[UnityPlugin sharedInstance] passViewController:rootViewController];
        NSString* result = [[UnityPlugin sharedInstance] configureWithIssuer:Kissuer clientID:KclientID redirectURI:KredirectURI];
        // Convert the resulting configuration NSString to a C-style string and return it
        return [result UTF8String];
        
    } else {
        // Root view controller is nil
        NSLog(@"Root view controller is nil");
        // Convert the resulting configuration NSString to a C-style string and return it
        return [@"Root view controller is nil" UTF8String];
        
    }
}

//const char* configureAppAuthManager(char* issuer, const char* clientID, const char* redirectURI,  char* redirectURI1){
//    // Convert C-style strings to NSString
//    NSString* Kissuer = [NSString stringWithUTF8String:issuer];
//    NSString* KclientID = [NSString stringWithUTF8String:clientID];
//    NSString* KredirectURI = [NSString stringWithUTF8String:redirectURI];
//    NSString* KredirectURI1 = [NSString stringWithUTF8String:redirectURI1];
//
//
//    KredirectURI = [KredirectURI stringByAppendingString: @":/"];
//    KredirectURI = [KredirectURI stringByAppendingString:KredirectURI1];
//
//    // Your implementation for the configureAppAuthManager method
//    UIWindow *mainWindow = [UIApplication sharedApplication].delegate.window;
//
//    // Access the root view controller
//    UIViewController *rootViewController = mainWindow.rootViewController;
//
//
//    if (rootViewController) {
//        // Root view controller exists
//        NSLog(@"Root view controller is not nil");
//
//        [[UnityPlugin sharedInstance] passViewController:rootViewController];
//        NSString* result = [[UnityPlugin sharedInstance] configureWithIssuer:Kissuer clientID:KclientID redirectURI:KredirectURI];
//        // Convert the resulting configuration NSString to a C-style string and return it
//        return [result UTF8String];
//
//    } else {
//        // Root view controller is nil
//        NSLog(@"Root view controller is nil");
//        // Convert the resulting configuration NSString to a C-style string and return it
//        return [@"Root view controller is nil" UTF8String];
//
//    }
//}

const char* getAccessToken(){
    NSString *result = [[UnityPlugin sharedInstance] getAccessToken];
    return [result UTF8String];
}
const char* getAccessTokenExpiryDateAsString(){
    NSString *result = [[UnityPlugin sharedInstance] getAccessTokenExpiryDateAsString];
    return [result UTF8String];
}

int getAccessTokenExpiryInSeconds(){
    NSInteger result = [[UnityPlugin sharedInstance] getAccessTokenExpiryInSeconds];
    return (int)result;
}

bool isAccessTokenExpired(){
    Boolean result = [[UnityPlugin sharedInstance] isAccessTokenExpired];
    return result;
}

const char* getRefreshToken(){
    NSString *result = [[UnityPlugin sharedInstance] getRefreshToken];
    return [result UTF8String];
}
int getRefreshTokenExpiryInSeconds(){
    NSInteger result = [[UnityPlugin sharedInstance] getRefreshTokenExpiryInSeconds];
    return (int)result;
}
bool isRefreshTokenExpired(){
    Boolean result = [[UnityPlugin sharedInstance] isRefreshTokenExpired];
    return result;
}



typedef void (*LoginCompletionHandler)(bool isSuccess,const char* accessToken, const char* lastResponse,const char* errString );
void login(LoginCompletionHandler completionHandler) {
    [[UnityPlugin sharedInstance] loginWithCompletionHandler:^(BOOL isSuccess, NSString *accessToken, NSString *lastResponse,NSString *errString)  {
        // Handle the returned values here
        if (errString != nil) {
            NSLog(@"Error: %@", errString);
        } else {
            NSLog(@"User Info: %@", accessToken);
        }
        completionHandler(isSuccess,[accessToken UTF8String],[lastResponse UTF8String],[errString UTF8String]);
        
    }];
}


typedef void (*UserInfoCallback)(bool isSuccess, const char* userInfo, const char* errString);

void getUserInfo(UserInfoCallback completionHandler) {
    [[UnityPlugin sharedInstance] getUserInfoWithCompletion:^(BOOL isSuccess, NSString *userInfo, NSString *errString) {
        // Handle the returned values here
        if (errString != nil) {
            NSLog(@"Error: %@", errString);
        } else {
            NSLog(@"User Info: %@", userInfo);
        }
        
        completionHandler(isSuccess,[userInfo UTF8String],[errString UTF8String]);
    }];
}



typedef void (*RefreshTokenCallback)(bool isSuccess,const char* accessToken, const char* lastResponse,const char* errString);
void refreshTokenRequest(RefreshTokenCallback completionHandler) {
    [[UnityPlugin sharedInstance] refreshTokenRequestWithCompletion:^(BOOL isSuccess, NSString *accessToken, NSString *lastResponse,NSString *errString) {
        // Handle the returned values here
        if (errString != nil) {
            NSLog(@"Error: %@", errString);
        } else {
            NSLog(@"User Access Token: %@", accessToken);
        }
        
        completionHandler(isSuccess,[accessToken UTF8String], [lastResponse UTF8String],[errString UTF8String]);
    }];
}


typedef void (*LogoutCompletionHandler)(bool isLogout, const char* errString);
void logout(LogoutCompletionHandler completionHandler) {
    
    [[UnityPlugin sharedInstance] logoutWithCompletion:^(BOOL isLogout, NSString* errString) {
        return completionHandler(isLogout,[errString UTF8String]);
    }];
}
}
