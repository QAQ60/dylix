#import <Foundation/Foundation.h>
#import "../AIContracts.h"
@class UIViewController;
@interface TFAIOAuth : NSObject
+ (instancetype)shared;
- (BOOL)hasCredential:(NSString *)identifier;
- (void)login:(NSDictionary *)connection presenter:(UIViewController *)presenter completion:(TFAIResult)completion;
- (void)credential:(NSDictionary *)connection completion:(void(^)(NSString *token,NSError *error))completion;
// WorkBuddy 登录时随凭据一起保存的账户附加信息（uid、domain、企业 ID 等）。
- (NSDictionary *)storedRecord:(NSString *)identifier;
- (void)logout:(NSDictionary *)connection completion:(TFAIResult)completion;
@end
