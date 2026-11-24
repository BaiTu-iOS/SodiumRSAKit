//
//  BTViewController.m
//  BTCrypto
//
//  Created by yuxilong on 07/12/2022.
//  Copyright (c) 2022 yuxilong. All rights reserved.
//

#import "BTViewController.h"
#import <BTCrypto/BTCrypto.h>
#import <BTCrypto/SodiumObjc.h>

@interface BTViewController ()

@end

@implementation BTViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.

    NACLAsymmetricKeyPair *sender = [[NACLAsymmetricKeyPair alloc] init];
    NACLAsymmetricKeyPair *recipient = [[NACLAsymmetricKeyPair alloc] init];
    NSString *nonce = nil;
    NSString *ciphertext = [SodiumCrypto encrypt:@"Hello, world!"
                                       publicKey:[recipient.publicKey.data base64EncodedStringWithOptions:0]
                                      privateKey:[sender.privateKey.data base64EncodedStringWithOptions:0]
                                     nonceString:&nonce];
    NSData *plaintext = [SodiumCrypto decrypt:ciphertext
                                    publicKey:[sender.publicKey.data base64EncodedStringWithOptions:0]
                                   privateKey:[recipient.privateKey.data base64EncodedStringWithOptions:0]
                                  nonceString:nonce];
    self.title = [[NSString alloc] initWithData:plaintext encoding:NSUTF8StringEncoding];
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
