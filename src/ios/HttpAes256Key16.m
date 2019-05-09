/********* HttpAes256Key16.m Cordova Plugin Implementation *******/

#import <Cordova/CDV.h>
#import <CommonCrypto/CommonCryptor.h>


@interface HttpAes256Key16 : CDVPlugin {
  //在这里声明变量
}

- (void)coolMethod:(CDVInvokedUrlCommand*)command;
- (void)Encrypt:(CDVInvokedUrlCommand*)command;
- (void)Decrypt:(CDVInvokedUrlCommand*)command;
@end

@implementation HttpAes256Key16

//测试插件
- (void)coolMethod:(CDVInvokedUrlCommand*)command
{
    CDVPluginResult* pluginResult = nil;
    NSString* echo = [command.arguments objectAtIndex:0];

    if (echo != nil && [echo length] > 0) {
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:echo];
    } else {
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR];
    }

    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (NSData *)AesEncryptWithKey:(NSString *)key vector:(NSString *)vector Encrypttext:(NSData *)text
{
    const char *iv = [vector cStringUsingEncoding:NSUTF8StringEncoding];

    char keyPtr[kCCKeySizeAES128+1];
    bzero(keyPtr, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    NSUInteger dataLength = [text length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    size_t numBytesEncrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt,
                                          kCCAlgorithmAES,
                                          kCCOptionPKCS7Padding,
                                          keyPtr,
                                          kCCBlockSizeAES128,
                                          iv,
                                          [text bytes], dataLength,
                                          buffer, bufferSize,
                                          &numBytesEncrypted);
    if (cryptStatus == kCCSuccess) {
        return [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
    }
    free(buffer);
    return nil;
}

- (NSData *)AesDecryptWithKey:(NSString *)key vector:(NSString *)vector Decrypttext:(NSData *)text
{
    const char *iv = [vector cStringUsingEncoding:NSUTF8StringEncoding];
    char keyPtr[kCCKeySizeAES128+1];
    bzero(keyPtr, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    NSUInteger dataLength = [text length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    size_t numBytesDecrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding,
                                          keyPtr,
                                          kCCBlockSizeAES128,
                                          iv,
                                          [text bytes], dataLength,
                                          buffer, bufferSize,
                                          &numBytesDecrypted);
    if (cryptStatus == kCCSuccess) {
        return [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
    }
    free(buffer);
    return nil;
}

//加密
- (void)Encrypt:(CDVInvokedUrlCommand*)command
//(NSString *)text privatekey:(NSString *)privatekey vector:(NSString *)vector
{
    //声明变量
    CDVPluginResult* pluginResult = nil;
    NSString* privatekey = [command.arguments objectAtIndex:0];
    NSString* vector = [command.arguments objectAtIndex:1];
    NSString* text = [command.arguments objectAtIndex:2];
    NSString* echo;

    //执行并接收返回值
    NSData *data=[text dataUsingEncoding:NSUTF8StringEncoding];
    NSData *result = [self AesEncryptWithKey:privatekey vector:vector Encrypttext:data];

    //成功回调
    echo = [result base64EncodedStringWithOptions:NSDataBase64EncodingEndLineWithLineFeed];
    pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:echo];

    //执行回调处理
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

//解密
- (void)Decrypt:(CDVInvokedUrlCommand*)command
//(NSString *)text privatekey:(NSString *)privatekey vector:(NSString *)vector
{
    //声明变量
    CDVPluginResult* pluginResult = nil;
    NSString* privatekey = [command.arguments objectAtIndex:0];
    NSString* vector = [command.arguments objectAtIndex:1];
    NSString* text = [command.arguments objectAtIndex:2];
    NSString* echo;

    //执行并接收返回值
    NSData* result = [self DecryptData:text privatekey:privatekey vector:vector];

    //进行判断
    if (result && result.length > 0) {
        echo = [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
        //成功回调
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:echo];
    }else {
        //失败回调
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR];
    }

    //执行回调处理
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (NSData *) DecryptData:(NSString *)text privatekey:(NSString *)privatekey vector:(NSString *)vector
{
    NSMutableData *data = [[NSData alloc] initWithBase64EncodedString:text options:NSDataBase64DecodingIgnoreUnknownCharacters];
    NSData* result = [self  AesDecryptWithKey:privatekey vector:vector Decrypttext:data];

    return result;
}

@end
