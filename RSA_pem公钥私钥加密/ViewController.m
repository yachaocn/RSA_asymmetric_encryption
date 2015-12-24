//
//  ViewController.m
//  RSA_pem公钥私钥加密
//
//  Created by yachaocn on 15/12/15.
//  Copyright © 2015年 NavchinaMacBook. All rights reserved.
//

#import "ViewController.h"
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/md5.h>
//MD5生成
#import <CommonCrypto/CommonDigest.h>
#define FileHashDefaultChunkSizeForReadingData 1024*8

#define kPublicKeyFile [[NSBundle mainBundle] pathForResource:@"public_key" ofType:@"pem"] //公钥路径
#define kPrivateKeyFile [[NSBundle mainBundle] pathForResource:@"private_key" ofType:@"pem"] //私钥路径

#define kContentTxt @"kumadocs.com"//需要加密数据

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
//    注意此项目中缺少openSSL三方库请到我的百度网盘下载http://pan.baidu.com/s/1c0Oczj6
    
    // Do any additional setup after loading the view, typically from a nib.
    
    //密文
    unsigned char encrypted[1024];
    bzero(encrypted, sizeof(encrypted));
    
    //明文
    char decrypted[1024];
    
    //公钥和私钥文件
    const char* pub_key = [kPublicKeyFile UTF8String];
    const char* priv_key = [kPrivateKeyFile UTF8String];
    
    // -------------------------------------------------------
    // 利用公钥加密明文的过程
    // -------------------------------------------------------
    RSA *rsa1 = NULL;
    const char *contentChar = [kContentTxt UTF8String];
    
    FILE* pub_fp=fopen(pub_key,"r");
    if(pub_fp==NULL){
        printf("Open Failed!! The Pub_Key File : %s!\n", pub_key);
        return ;
    }
    
    // 从文件中读取公钥
    rsa1 = PEM_read_RSA_PUBKEY(pub_fp, NULL, NULL, NULL);
    if(rsa1 == NULL){
        printf("Pub_Key Read Failure!!\n");
        return ;
    }
    
    if(strlen(contentChar) >= RSA_size(rsa1)-41){
        printf("Encrypt Failed!!\n");
        return ;
    }
    fclose(pub_fp);
    
    
    // 用公钥加密 （如需私钥加密将如下函数换成RSA_private_encrypt即可）
    int state = RSA_public_encrypt (strlen(contentChar), (const unsigned char*)contentChar, encrypted, rsa1, RSA_PKCS1_PADDING);
    if( state == -1 ){
        printf("Encrypt Failed!!");
        return ;
    }
    
    
    // ---------------------------
    // 输出加密后的密文
    NSString *encryptedTxt = @"";
    for (int i = 0; i < 128; i++) {//注意128按需要的自行改
        encryptedTxt = [encryptedTxt stringByAppendingFormat:@"%02x",encrypted[i]];
    }
    NSLog(@"encryptedTxt == 》 \n\n%@\n\n",encryptedTxt);
    
    
    
    // -------------------------------------------------------
    // 利用私钥解密密文的过程
    // -------------------------------------------------------
    
    // 打开私钥文件
    FILE* priv_fp=fopen(priv_key,"r");
    if(priv_fp==NULL){
        printf("Open Failed!! The Priv_Key File :%s!\n", priv_key);
        return ;
    }
    
    
    // 从文件中读取私钥
    RSA *rsa2 = PEM_read_RSAPrivateKey(priv_fp, NULL, NULL, NULL);
    if(rsa2==NULL){
        printf("Priv_Key Read Failure!!\n");
        return ;
    }
    
    // 用私钥解密 （如需公钥解密只需将如下函数改成RSA_public_decrypt即可）
    state = RSA_private_decrypt(state, encrypted, decrypted, rsa2, RSA_PKCS1_PADDING);
    if(state == -1){
        printf("Decrypt Failed!!\n");
        return ;
    }
    fclose(priv_fp);

    // 输出解密后的明文
    decrypted[state]=0;
    printf("decrypted == 》%s\n",decrypted);
    
    NSString *opensslMD5 = [self genaryMD5FromString:@"12345"];
    NSLog(@"openssl>>>>md5:%@",opensslMD5);
    NSString *commonDigestMD5 = [ViewController md5HexDigest:@"12345"];
    NSLog(@"commonDigestMD5 >>>:%@",commonDigestMD5);
    
    /**
     *
     * 打印出来的结果
     */
    /*
     2015-12-22 10:25:43.241 RSA_pem公钥私钥加密[1804:89084] 
     encryptedTxt == 》8b4f003797194009716f7239bc336b8be80561ddc07bb0ce0498c6de0740244f4205c6cac19b49a461d0a1f927677507eb8c2261cc06eada177ea341008b559100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
     
     decrypted == 》kumadocs.com
     
     2015-12-22 10:25:43.253 RSA_pem公钥私钥加密[1804:89084] input string:12345
     2015-12-22 10:25:43.253 RSA_pem公钥私钥加密[1804:89084] md5:                 827ccb0eea8a706c4c34a16891f84e7b
     2015-12-22 10:25:43.254 RSA_pem公钥私钥加密[1804:89084] openssl>>>>md5:      827ccb0eea8a706c4c34a16891f84e7b
     2015-12-22 10:25:43.254 RSA_pem公钥私钥加密[1804:89084] commonDigestMD5 >>>: 827ccb0eea8a706c4c34a16891f84e7b

     */
    
    
    
}
//openssl计算MD5

-(NSString *)genaryMD5FromString:(NSString *)string
{
    // 输入参数 1 ：要生成 md5 值的字符串， NSString-->uchar*
    
    unsigned char *inStrg = ( unsigned char *)[[string dataUsingEncoding : NSASCIIStringEncoding ] bytes];
    
    // 输入参数 2 ：字符串长度
    
    unsigned long lngth = [string length ];
    
    // 输出参数 3 ：要返回的 md5 值， MD5_DIGEST_LENGTH 为 16bytes ， 128 bits
    
    unsigned char result[ MD5_DIGEST_LENGTH ];
    
    // 临时 NSString 变量，用于把 uchar* 组装成可以显示的字符串： 2 个字符一 byte 的 16 进制数
    
    NSMutableString *outStrg = [ NSMutableString string ];
    
    // 调用 OpenSSL 函数
    
    MD5 (inStrg, lngth, result);
    
    unsigned int i;
    
    for (i = 0; i < MD5_DIGEST_LENGTH ; i++)
        
    {
        
        [outStrg appendFormat : @"%02x" , result[i]];
        
    }
    
    NSLog ( @"input string:%@" ,string);
    
    NSLog ( @"md5:%@" ,outStrg);
    return outStrg;
}

//系统函数计算MD5值如下

+ (NSString *)md5HexDigest:(NSString*)password
{
    
    const char *original_str = [password UTF8String];
    
    unsigned char result[CC_MD5_DIGEST_LENGTH];
    
    CC_MD5(original_str, strlen(original_str), result);
    
    NSMutableString *hash = [NSMutableString string];
    
    for (int i = 0; i < 16; i++){
        [hash appendFormat:@"%02X", result[i]];
    }
    
    NSString *mdfiveString = [hash lowercaseString];
    
    //    NSLog(@"Encryption Result = %@",mdfiveString);
    
    return mdfiveString;
    
}

//系统函数计算文件的MD5

+(NSString*)getFileMD5WithPath:(NSString*)path

{
    
    return (__bridge_transfer NSString *)FileMD5HashCreateWithPath((__bridge CFStringRef)path, FileHashDefaultChunkSizeForReadingData);
    
}



CFStringRef FileMD5HashCreateWithPath(CFStringRef filePath,size_t chunkSizeForReadingData) {
    
    // Declare needed variables
    
    CFStringRef result = NULL;
    
    CFReadStreamRef readStream = NULL;
    
    // Get the file URL
    
    CFURLRef fileURL =
    
    CFURLCreateWithFileSystemPath(kCFAllocatorDefault,
                                  
                                  (CFStringRef)filePath,
                                  
                                  kCFURLPOSIXPathStyle,
                                  
                                  (Boolean)false);
    
    if (!fileURL) goto done;
    
    // Create and open the read stream
    
    readStream = CFReadStreamCreateWithFile(kCFAllocatorDefault,
                                            
                                            (CFURLRef)fileURL);
    
    if (!readStream) goto done;
    
    bool didSucceed = (bool)CFReadStreamOpen(readStream);
    
    if (!didSucceed) goto done;
    
    // Initialize the hash object
    
    CC_MD5_CTX hashObject;
    
    CC_MD5_Init(&hashObject);
    
    // Make sure chunkSizeForReadingData is valid
    
    if (!chunkSizeForReadingData) {
        
        chunkSizeForReadingData = FileHashDefaultChunkSizeForReadingData;
        
    }
    
    // Feed the data to the hash object
    
    bool hasMoreData = true;
    
    while (hasMoreData) {
        
        uint8_t buffer[chunkSizeForReadingData];
        
        CFIndex readBytesCount = CFReadStreamRead(readStream,(UInt8 *)buffer,(CFIndex)sizeof(buffer));
        
        if (readBytesCount == -1) break;
        
        if (readBytesCount == 0) {
            
            hasMoreData = false;
            
            continue;
            
        }
        
        CC_MD5_Update(&hashObject,(const void *)buffer,(CC_LONG)readBytesCount);
        
    }
    
    // Check if the read operation succeeded
    
    didSucceed = !hasMoreData;
    
    // Compute the hash digest
    
    unsigned char digest[CC_MD5_DIGEST_LENGTH];
    
    CC_MD5_Final(digest, &hashObject);
    
    // Abort if the read operation failed
    
    if (!didSucceed) goto done;
    
    // Compute the string result
    
    char hash[2 * sizeof(digest) + 1];
    
    for (size_t i = 0; i < sizeof(digest); ++i) {
        
        snprintf(hash + (2 * i), 3, "%02x", (int)(digest[i]));
        
    }
    
    result = CFStringCreateWithCString(kCFAllocatorDefault,(const char *)hash,kCFStringEncodingUTF8);
    
    
    
done:
    
    if (readStream) {
        
        CFReadStreamClose(readStream);
        
        CFRelease(readStream);
        
    }
    
    if (fileURL) {
        
        CFRelease(fileURL);
        
    }
    
    return result;
    
}




- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
