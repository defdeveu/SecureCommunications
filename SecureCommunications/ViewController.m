//
//  ViewController.m
//  SecureCommunications
//
//  Created by Zsombor on 2019. 04. 27..
//  Copyright © 2019. Zsombor. All rights reserved.
//
#import "AppDelegate.h"
#import "ViewController.h"
#import "RSA.h"
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>

@interface ViewController ()
- (IBAction)sendButtonPressed:(id)sender;
@property (weak, nonatomic) IBOutlet UITextField *responseTextField;

@end

@implementation NSData (AES256)

- (NSData *)AES256EncryptWithKey:(NSString *)key withIv:(NSString *)iv {
    // 'key' should be 32 bytes for AES256, will be null-padded otherwise
    char keyPtr[kCCKeySizeAES256+1]; // room for terminator (unused)
    bzero(keyPtr, sizeof(keyPtr)); // fill with zeroes (for padding)
    
    char ivPtr[17]; // room for terminator (unused)
    bzero(ivPtr, sizeof(ivPtr));
    
    // fetch key data
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    [iv getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = [self length];
    
    //See the doc: For block ciphers, the output size will always be less than or
    //equal to the input size plus the size of one block.
    //That's why we need to add the size of one block here
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    
    size_t numBytesEncrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
                                          keyPtr, kCCKeySizeAES256,
                                          ivPtr /* initialization vector (optional) */,
                                          [self bytes], dataLength, /* input */
                                          buffer, bufferSize, /* output */
                                          &numBytesEncrypted);
    if (cryptStatus == kCCSuccess) {
        //the returned NSData takes ownership of the buffer and will free it on deallocation
        return [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
    }
    
    free(buffer); //free the buffer;
    return nil;
}

- (NSData *)AES256DecryptWithKey:(NSString *)key {
    // 'key' should be 32 bytes for AES256, will be null-padded otherwise
    char keyPtr[kCCKeySizeAES256+1]; // room for terminator (unused)
    bzero(keyPtr, sizeof(keyPtr)); // fill with zeroes (for padding)
    
    
    // fetch key data
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = [self length];
    
    //See the doc: For block ciphers, the output size will always be less than or
    //equal to the input size plus the size of one block.
    //That's why we need to add the size of one block here
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    
    size_t numBytesDecrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
                                          keyPtr, kCCKeySizeAES256,
                                          NULL /* initialization vector (optional) */,
                                          [self bytes], dataLength, /* input */
                                          buffer, bufferSize, /* output */
                                          &numBytesDecrypted);
    
    if (cryptStatus == kCCSuccess) {
        //the returned NSData takes ownership of the buffer and will free it on deallocation
        return [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
    }
    
    free(buffer); //free the buffer;
    return nil;
}

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
}

- (NSData *)encryptRSA:(NSString *)msg withPubKey:(NSString *) pubKey {
    NSData *ret = [RSA encryptData:[msg dataUsingEncoding:NSUTF8StringEncoding] publicKey:pubKey];
    return ret;
}

- (NSData *)signRSA:(NSData *)msg withPrivKey:(NSString *) privKey {
    uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    
    NSLog(@"Signing...");
    
    CC_SHA1(msg.bytes, (CC_LONG)msg.length, digest);
    
    NSData *digestData = [NSData dataWithBytes:digest length:CC_SHA1_DIGEST_LENGTH];
    NSLog(@"digestData = %@", digestData);
    
    NSData *signature = [RSA encryptData:digestData privateKey:privKey];
    NSLog(@"signature = %@", signature);

    return signature;
}

- (NSData *) encryptAES:(NSString*)plaintext withKey:(NSString*)key withIv:(NSString *)iv{
    return [[plaintext dataUsingEncoding:NSUTF8StringEncoding] AES256EncryptWithKey:key withIv:iv];
}

- (NSString *) decryptAES:(NSString *)ciphertext withKey:(NSString*)key {
    NSData *data = [[NSData alloc] initWithBase64EncodedString:ciphertext options:kNilOptions];
    return [[NSString alloc] initWithData:[data AES256DecryptWithKey:key] encoding:NSUTF8StringEncoding];
}

- (NSString *) sendRequest:(NSString *)reqtext {
    NSString *endpoint = @"https://zs.labs.defdev.eu:9998/request";
    NSURLSessionConfiguration *sessionConfiguration = [NSURLSessionConfiguration defaultSessionConfiguration];
    NSURLSession *session = [NSURLSession sessionWithConfiguration:sessionConfiguration];
    NSURL *url = [NSURL URLWithString:endpoint];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    [request addValue:@"application/text" forHTTPHeaderField:@"Content-type"];
    request.HTTPBody = [reqtext dataUsingEncoding:NSUTF8StringEncoding];
    request.HTTPMethod = @"POST";
    NSURLSessionDataTask *postDataTask = [session dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        dispatch_async(dispatch_get_main_queue(), ^{ // Correct
            NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *) response;
            NSString *inStr = [NSString stringWithFormat:@"%ld", [httpResponse statusCode]];
            self->_responseTextField.text = inStr;
        });
        
    }];
    [postDataTask resume];
    
    return @"";
}


- (IBAction)sendButtonPressed:(id)sender {
    NSString* serverPubPath = [[NSBundle mainBundle] pathForResource:@"server-pub-pkcs8"
                                                     ofType:@"pem"];
    NSString* serverPubKey = [NSString stringWithContentsOfFile:serverPubPath
                                                   encoding:NSUTF8StringEncoding
                                                      error:NULL];
    
    NSString* clientPrivPath = [[NSBundle mainBundle] pathForResource:@"private-pkcs8"
                                                               ofType:@"pem"];
    NSString* clientPrivKey = [NSString stringWithContentsOfFile:clientPrivPath
                                                        encoding:NSUTF8StringEncoding
                                                           error:NULL];

    NSString* clientPubPath = [[NSBundle mainBundle] pathForResource:@"public-pkcs8"
                                                               ofType:@"pem"];
    NSString* clientPubKey = [NSString stringWithContentsOfFile:clientPrivPath
                                                        encoding:NSUTF8StringEncoding
                                                           error:NULL];
    _responseTextField.text = @"Trying...";
    
    NSString *aesKey = @"00112233445566778899aabbccddeeff";
    NSString *aesData = @"00112233445566778899aabbccddeeff|1111111111111111";
    NSString *iv = @"1111111111111111";
    NSData *encryptedAESKey = [self encryptRSA:aesData withPubKey:serverPubKey];
    NSLog(@"encrypted AES key: %@", encryptedAESKey);
    
    NSString *message = @"The answer is noThe answer is no";
    NSData *encMessage = [self encryptAES:message withKey:aesKey withIv:iv];
    NSLog(@"encrypted message: %@",encMessage);
    
    NSData *signature = [self signRSA:encMessage withPrivKey:clientPrivKey];
    NSLog(@"signature: %@",signature);
    
    NSString *reqtext = [NSString stringWithFormat:@"<request><enckey>%@</enckey><message>%@</message><signature>%@</signature></request>",
        [encryptedAESKey base64EncodedStringWithOptions:0],
        [encMessage base64EncodedStringWithOptions:0],
        [signature base64EncodedStringWithOptions:0]
    ];
    NSLog(@"%@", reqtext);
    [self sendRequest:reqtext];
}
@end
