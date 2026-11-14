#import "TFAIOAuth.h"
#import "TFAIRegistry.h"
#import "TFAIProtocol.h"
#import <AuthenticationServices/AuthenticationServices.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
static NSError *AuthError(NSString *message){return TFAIError(401,message);}
static NSString *B64(NSData *d){return [[[[d base64EncodedStringWithOptions:0] stringByReplacingOccurrencesOfString:@"+" withString:@"-"] stringByReplacingOccurrencesOfString:@"/" withString:@"_"] stringByReplacingOccurrencesOfString:@"=" withString:@""];}
static BOOL OfficialBase(NSURL *url,NSURL *official){return [url.scheme.lowercaseString isEqual:@"https"]&&[url.host.lowercaseString isEqual:official.host.lowercaseString]&&(!url.port||url.port.integerValue==443)&&!url.user&&!url.password&&!url.query&&!url.fragment&&[url.path.stringByStandardizingPath isEqual:official.path.stringByStandardizingPath];}
static NSString *Random(void){uint8_t bytes[32];if(SecRandomCopyBytes(kSecRandomDefault,sizeof(bytes),bytes)!=errSecSuccess)return nil;return B64([NSData dataWithBytes:bytes length:sizeof(bytes)]);}
static NSMutableDictionary *TokenQuery(NSString *identifier){return [@{(__bridge id)kSecClass:(__bridge id)kSecClassGenericPassword,(__bridge id)kSecAttrService:@"com.xuegao.dylix.ai.oauth.v1",(__bridge id)kSecAttrAccount:identifier?:@""} mutableCopy];}
static NSDictionary *ReadToken(NSString *identifier){NSMutableDictionary *q=TokenQuery(identifier);q[(__bridge id)kSecReturnData]=@YES;CFTypeRef result=NULL;if(SecItemCopyMatching((__bridge CFDictionaryRef)q,&result)!=errSecSuccess)return nil;NSData *d=CFBridgingRelease(result);id j=[NSJSONSerialization JSONObjectWithData:d options:0 error:nil];return [j isKindOfClass:NSDictionary.class]?j:nil;}
static BOOL SaveToken(NSString *identifier,NSDictionary *record){NSData *data=[NSJSONSerialization dataWithJSONObject:record options:0 error:nil];if(!data)return NO;NSMutableDictionary *q=TokenQuery(identifier);OSStatus status=SecItemUpdate((__bridge CFDictionaryRef)q,(__bridge CFDictionaryRef)@{(__bridge id)kSecValueData:data});if(status==errSecItemNotFound){q[(__bridge id)kSecValueData]=data;q[(__bridge id)kSecAttrAccessible]=(__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;status=SecItemAdd((__bridge CFDictionaryRef)q,NULL);}return status==errSecSuccess;}
static NSData *Form(NSDictionary *fields){NSMutableArray *pairs=[NSMutableArray new];NSCharacterSet *allowed=[NSCharacterSet characterSetWithCharactersInString:@"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"];for(NSString *key in fields)[pairs addObject:[NSString stringWithFormat:@"%@=%@",[key stringByAddingPercentEncodingWithAllowedCharacters:allowed],[[fields[key] description] stringByAddingPercentEncodingWithAllowedCharacters:allowed]]];return [[pairs componentsJoinedByString:@"&"] dataUsingEncoding:NSUTF8StringEncoding];}
// WorkBuddy（腾讯 CodeBuddy 计划）：桌面客户端的外链登录。申请 state 与授权页，
// 用户在页面（中国区 login.codebuddy.cn / 国际版 www.workbuddy.ai，页面即扫码页）
// 完成登录后，客户端每秒轮询 token 与账户接口，直到拿到凭据。没有回调与 client id。
// 协议来自 WorkBuddy 桌面客户端，与 kwwk（EYHN/kwwk）的 WorkBuddyOAuth.swift 一致。
static NSString *const TFWorkBuddyAppVersion=@"2.0.0";           // 登录页被告知的插件版本
static NSString *const TFWorkBuddyClientVersion=@"5.5.6";        // 网关拒绝陌生客户端版本（10085）
static NSString *WorkBuddyUserAgent(void){return [NSString stringWithFormat:@"WorkBuddy/%@",TFWorkBuddyClientVersion];}
static NSInteger const TFWorkBuddyTokenPendingCode=11217;        // token 未就绪
static NSInteger const TFWorkBuddyAccountPendingCode=12151;      // 账户未就绪
static NSTimeInterval const TFWorkBuddySignInWindow=5*60;        // 登录页等待上限
static NSTimeInterval const TFWorkBuddyExpiryMargin=5*60;        // 提前 5 分钟续期
static NSDictionary *WorkBuddySite(NSDictionary *oauth){NSString *platform=[oauth[@"platform"] isKindOfClass:NSString.class]?oauth[@"platform"]:@"";
 NSString *endpoint=[oauth[@"endpoint"] isKindOfClass:NSString.class]?oauth[@"endpoint"]:@"";
 if(endpoint.length){while([endpoint hasSuffix:@"/"])endpoint=[endpoint substringToIndex:endpoint.length-1];return @{@"platform":platform.length?platform:@"workbuddy",@"endpoint":endpoint};}
 // 兼容：未写 endpoint 时按 platform 推断官方地址。
 if([platform isEqual:@"workbuddy-ai"])return @{@"platform":platform,@"endpoint":@"https://www.workbuddy.ai"};
 return @{@"platform":platform.length?platform:@"workbuddy",@"endpoint":@"https://copilot.tencent.com"};}
static NSString *WorkBuddyHex(void){uint8_t bytes[16];if(SecRandomCopyBytes(kSecRandomDefault,sizeof(bytes),bytes)!=errSecSuccess)return nil;NSMutableString *out=[NSMutableString new];for(NSUInteger i=0;i<sizeof(bytes);i++)[out appendFormat:@"%02x",bytes[i]];return out;}
// WorkBuddy 的 JSON 应答包着 {code,msg,data}：code 0 才算成功，与 HTTP 状态无关。
static NSError *WorkBuddyEnvelope(NSDictionary *json,NSInteger status,NSDictionary **data){NSInteger code=[json[@"code"] isKindOfClass:NSNumber.class]?[json[@"code"] integerValue]:0;NSString *said=[json[@"msg"] isKindOfClass:NSString.class]?json[@"msg"]:@"";
 if(code!=0){return TFAIError(code,said.length?said:[NSString stringWithFormat:@"服务返回错误码 %ld",(long)code]);}
 if(status<200||status>=300){return TFAIError(status,said.length?said:[NSString stringWithFormat:@"HTTP %ld",(long)status]);}
 if(data)*data=[json[@"data"] isKindOfClass:NSDictionary.class]?json[@"data"]:@{};return nil;}
static NSDictionary *WorkBuddyAccountHeaders(NSDictionary *record,NSDictionary *site){NSMutableDictionary *h=[NSMutableDictionary new];NSString *uid=[record[@"uid"] isKindOfClass:NSString.class]?record[@"uid"]:@"";
 NSURL *url=[NSURL URLWithString:site[@"endpoint"]];NSString *domain=[record[@"domain"] isKindOfClass:NSString.class]&&[record[@"domain"] length]?record[@"domain"]:(url.host?:@"");
 if(uid.length)h[@"X-User-Id"]=uid;if(domain.length)h[@"X-Domain"]=domain;
 NSString *enterprise=[record[@"enterpriseId"] isKindOfClass:NSString.class]?record[@"enterpriseId"]:@"";if(enterprise.length){h[@"X-Enterprise-Id"]=enterprise;h[@"X-Tenant-Id"]=enterprise;}return h;}
static NSDictionary *WorkBuddyJSONHeaders(void){return @{@"Content-Type":@"application/json",@"Accept":@"application/json",@"User-Agent":WorkBuddyUserAgent()};}
// 帐户产品头：所有聊天与计费请求都带；缺了会被计入无客户端用量。
static NSDictionary *WorkBuddyProductHeaders(NSDictionary *site){NSMutableDictionary *h=[@{@"X-Product":@"SaaS",@"X-IDE-Type":@"WorkBuddy",@"User-Agent":WorkBuddyUserAgent(),@"X-Requested-With":@"XMLHttpRequest",@"X-Agent-Intent":@"craft",@"X-Agent-Purpose":@"conversation",@"X-IDE-Name":@"WorkBuddy",@"X-IDE-Version":TFWorkBuddyClientVersion} mutableCopy];
 if([site[@"platform"] isEqual:@"workbuddy-ai"])h[@"X-Agent-Type"]=@"main";return h;}
@interface TFAIOAuth () <ASWebAuthenticationPresentationContextProviding,NSURLSessionTaskDelegate>
@property ASWebAuthenticationSession *web;
@property(nonatomic,weak) UIViewController *presenter;
@property NSMutableDictionary<NSString *,NSMutableArray *> *waiters;
@property NSMutableDictionary<NSString *,NSNumber *> *epochs;
@property NSUInteger loginSerial;
@end
@implementation TFAIOAuth
+ (instancetype)shared{static id s;static dispatch_once_t once;dispatch_once(&once,^{s=[self new];});return s;}
- (instancetype)init{if((self=[super init])){_waiters=[NSMutableDictionary new];_epochs=[NSMutableDictionary new];}return self;}
- (BOOL)hasCredential:(NSString *)identifier{return [ReadToken(identifier)[@"accessToken"] length]>0;}
- (NSDictionary *)storedRecord:(NSString *)identifier{return ReadToken(identifier)?:@{};}
// WorkBuddy 的 JSON 接口请求：应答按 {code,msg,data} 解包，code 0 才算成功。
- (void)workBuddyCall:(NSURL *)url method:(NSString *)method headers:(NSDictionary *)headers body:(NSDictionary *)body completion:(void(^)(NSDictionary *,NSError *))completion{
 NSMutableURLRequest *r=[NSMutableURLRequest requestWithURL:url];r.HTTPMethod=method;r.timeoutInterval=45;
 for(NSString *name in headers)if([headers[name] isKindOfClass:NSString.class])[r setValue:headers[name] forHTTPHeaderField:name];
 if(body){NSData *d=[NSJSONSerialization dataWithJSONObject:body options:0 error:nil];r.HTTPBody=d?:[@"{}" dataUsingEncoding:NSUTF8StringEncoding];}
 else if([method isEqual:@"POST"])r.HTTPBody=[@"{}" dataUsingEncoding:NSUTF8StringEncoding];
 NSURLSession *s=[NSURLSession sessionWithConfiguration:NSURLSessionConfiguration.ephemeralSessionConfiguration];
 [[s dataTaskWithRequest:r completionHandler:^(NSData *d,NSURLResponse *response,NSError *error){
  NSInteger status=[(NSHTTPURLResponse *)response statusCode];
  NSDictionary *json=d.length&&d.length<1024*1024?[NSJSONSerialization JSONObjectWithData:d options:0 error:nil]:nil;json=[json isKindOfClass:NSDictionary.class]?json:@{};
  dispatch_async(dispatch_get_main_queue(),^{[s finishTasksAndInvalidate];
   if(error){completion(nil,TFAIError(error.code,error.localizedDescription?:@"网络请求失败"));return;}
   NSDictionary *data=nil;NSError *e=WorkBuddyEnvelope(json,status,&data);completion(data,e);});
 }] resume];}
// 把 WorkBuddy 返回的 token 合并进钥匙串记录：时间来自 at 毫秒或 in 秒；
// 未轮换的 refresh token 保留旧值；提前 5 分钟视为过期。
static NSDictionary *WorkBuddyMergeToken(NSDictionary *token,NSDictionary *base){
 NSString *access=[token[@"accessToken"] isKindOfClass:NSString.class]?token[@"accessToken"]:@"";if(!access.length)return nil;
 double now=NSDate.date.timeIntervalSince1970;double expires=0;
 if([token[@"expiresAt"] isKindOfClass:NSNumber.class]&&[token[@"expiresAt"] doubleValue]>0)expires=[token[@"expiresAt"] doubleValue]/1000.0;
 else if([token[@"expiresIn"] isKindOfClass:NSNumber.class]&&[token[@"expiresIn"] doubleValue]>0)expires=now+[token[@"expiresIn"] doubleValue];
 else expires=now+60*60;
 NSMutableDictionary *next=[NSMutableDictionary new];
 for(NSString *key in @[@"uid",@"domain",@"enterpriseId",@"accountName",@"tokenType"])if([base[key] isKindOfClass:NSString.class]&&[base[key] length])next[key]=base[key];
 for(NSString *key in @[@"domain",@"tokenType"])if([token[key] isKindOfClass:NSString.class]&&[token[key] length])next[key]=token[key];
 if([token[@"refreshExpiresAt"] isKindOfClass:NSNumber.class]&&[token[@"refreshExpiresAt"] doubleValue]>0)next[@"refreshExpiresAt"]=@([token[@"refreshExpiresAt"] longLongValue]);
 else if([token[@"refreshExpiresIn"] isKindOfClass:NSNumber.class]&&[token[@"refreshExpiresIn"] doubleValue]>0)next[@"refreshExpiresAt"]=@((long long)((now+[token[@"refreshExpiresIn"] doubleValue])*1000));
 NSString *rotated=[token[@"refreshToken"] isKindOfClass:NSString.class]?token[@"refreshToken"]:@"";NSString *old=[base[@"refreshToken"] isKindOfClass:NSString.class]?base[@"refreshToken"]:@"";
 next[@"accessToken"]=access;next[@"refreshToken"]=rotated.length?rotated:old;
 next[@"expiresAt"]=@(MAX(0,expires-TFWorkBuddyExpiryMargin));next[@"kind"]=@"workbuddy";next[@"clientID"]=@"";
 return next;}
// 每秒轮询一个 WorkBuddy 接口直到有数据；"未就绪"业务码、408、429 继续等，
// 连续三次网络故障终止，超登录窗口报超时。
- (void)pollWorkBuddy:(NSDictionary *)site path:(NSString *)path headers:(NSDictionary *)headers pendingCode:(NSInteger)pending deadline:(NSDate *)deadline delay:(NSTimeInterval)delay consecutive:(NSUInteger)consecutive completion:(void(^)(NSDictionary *,NSError *))completion{
 dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(delay*NSEC_PER_SEC)),dispatch_get_main_queue(),^{if(NSDate.date.timeIntervalSince1970>[deadline timeIntervalSince1970]){completion(nil,AuthError(@"登录等待超时，请重试。"));return;}
  [self workBuddyCall:[NSURL URLWithString:[site[@"endpoint"] stringByAppendingString:path]] method:@"GET" headers:headers body:nil completion:^(NSDictionary *data,NSError *error){
   if(!error){if([data isKindOfClass:NSDictionary.class]&&data.count){completion(data,nil);}else[self pollWorkBuddy:site path:path headers:headers pendingCode:pending deadline:deadline delay:1.0 consecutive:0 completion:completion];return;}
   if(error.code==pending||error.code==408||error.code==429){[self pollWorkBuddy:site path:path headers:headers pendingCode:pending deadline:deadline delay:1.0 consecutive:0 completion:completion];return;}
   // 传输层故障视为抖动，连续三次才放弃。
   if(consecutive+1<3){[self pollWorkBuddy:site path:path headers:headers pendingCode:pending deadline:deadline delay:1.0 consecutive:consecutive+1 completion:completion];return;}
   completion(nil,error);}];
 });}
// WorkBuddy 外链登录：申请 state 与授权页 → 打开页面（扫码）→ 轮询 token → 轮询账户。
- (void)loginWorkBuddy:(NSDictionary *)c oauth:(NSDictionary *)oauth presenter:(UIViewController *)presenter completion:(TFAIResult)completion{
 NSString *identifier=c[@"id"];
 if(self.web){completion(nil,AuthError(@"已有登录流程正在进行。"));return;}
 NSDictionary *site=WorkBuddySite(oauth);
 self.epochs[identifier]=@([self.epochs[identifier] unsignedIntegerValue]+1);self.presenter=presenter;NSUInteger loginSerial=++self.loginSerial;NSUInteger epoch=[self.epochs[identifier] unsignedIntegerValue];__weak typeof(self) weak=self;
 NSString *query=[NSString stringWithFormat:@"?platform=%@",[site[@"platform"] stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet characterSetWithCharactersInString:@"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"]]];
 NSMutableDictionary *startHeaders=[WorkBuddyJSONHeaders() mutableCopy];startHeaders[@"X-No-Authorization"]=@"true";startHeaders[@"X-No-User-Id"]=@"true";startHeaders[@"X-No-Enterprise-Id"]=@"true";startHeaders[@"X-No-Department-Info"]=@"true";
 [self workBuddyCall:[NSURL URLWithString:[site[@"endpoint"] stringByAppendingString:[@"/v2/plugin/auth/state" stringByAppendingString:query]]] method:@"POST" headers:startHeaders body:@{} completion:^(NSDictionary *started,NSError *failure){
  if(epoch!=[weak.epochs[identifier] unsignedIntegerValue]){completion(nil,AuthError(@"登录状态已变更，请重试。"));return;}
  if(failure||![started[@"state"] isKindOfClass:NSString.class]||![started[@"state"] length]||![started[@"authUrl"] isKindOfClass:NSString.class]){completion(nil,failure?:AuthError(@"服务商未返回登录页，请稍后重试。"));return;}
  NSString *state=started[@"state"];
  // 保留页面自带的查询串（含 %2B 编码），只替换 version 与 loginSessionId。
  NSURLComponents *page=[NSURLComponents componentsWithString:started[@"authUrl"]];
  if(!page||![[page.scheme lowercaseString] isEqual:@"https"]){completion(nil,AuthError(@"登录页地址无效，请稍后重试。"));return;}
  NSMutableArray *kept=[NSMutableArray new];
  if(page.percentEncodedQuery.length)for(NSString *pair in [page.percentEncodedQuery componentsSeparatedByString:@"&"]){NSArray *kv=[pair componentsSeparatedByString:@"="];NSString *name=[kv.firstObject stringByRemovingPercentEncoding]?:kv.firstObject;if(![name isEqual:@"version"]&&![name isEqual:@"loginSessionId"])[kept addObject:pair];}
  NSString *session=WorkBuddyHex();if(!session){completion(nil,AuthError(@"系统随机数生成失败，请重试。"));return;}
  [kept addObject:[NSString stringWithFormat:@"version=%@",TFWorkBuddyAppVersion]];
  [kept addObject:[NSString stringWithFormat:@"loginSessionId=%@",session]];
  page.percentEncodedQuery=[kept componentsJoinedByString:@"&"];
  if(!page.URL){completion(nil,AuthError(@"登录页地址无效，请稍后重试。"));return;}
  NSDate *deadline=[NSDate dateWithTimeIntervalSinceNow:TFWorkBuddySignInWindow];
  ASWebAuthenticationSession *web=[[ASWebAuthenticationSession alloc]initWithURL:page.URL callbackURLScheme:@"dylix" completionHandler:^(NSURL *callback,NSError *error){
   // 本流程没有回调地址；页面关闭不影响轮询，登录由轮询接口确认。
  }];
  weak.web=web;web.presentationContextProvider=weak;web.prefersEphemeralWebBrowserSession=YES;if(![web start]){weak.web=nil;}
  NSMutableDictionary *asAccount=[NSMutableDictionary new];
  // token 轮询成功后再拼账户请求头；此处先轮询 token。
  NSString *encodedState=[state stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet characterSetWithCharactersInString:@"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"]];
  [self pollWorkBuddy:site path:[NSString stringWithFormat:@"/v2/plugin/auth/token?state=%@",encodedState] headers:@{} pendingCode:TFWorkBuddyTokenPendingCode deadline:deadline delay:0.5 consecutive:0 completion:^(NSDictionary *token,NSError *tokenError){
   if(epoch!=[weak.epochs[identifier] unsignedIntegerValue]){completion(nil,AuthError(@"登录状态已变更，请重试。"));return;}
   if(tokenError){weak.web=nil;completion(nil,tokenError);return;}
   NSDictionary *record=WorkBuddyMergeToken(token,@{});
   if(!record){weak.web=nil;completion(nil,AuthError(@"服务商未返回凭据，请重新登录。"));return;}
   NSString *domain=[record[@"domain"] isKindOfClass:NSString.class]&&[record[@"domain"] length]?record[@"domain"]:([NSURL URLWithString:site[@"endpoint"]].host?:site[@"endpoint"]);
   asAccount[@"Authorization"]=[NSString stringWithFormat:@"Bearer %@",record[@"accessToken"]];asAccount[@"X-Domain"]=domain;asAccount[@"X-No-User-Id"]=@"true";asAccount[@"X-No-Enterprise-Id"]=@"true";
   [self pollWorkBuddy:site path:[NSString stringWithFormat:@"/v2/plugin/login/account?state=%@",encodedState] headers:asAccount pendingCode:TFWorkBuddyAccountPendingCode deadline:deadline delay:0.5 consecutive:0 completion:^(NSDictionary *account,NSError *accountError){
    if(epoch!=[weak.epochs[identifier] unsignedIntegerValue]){completion(nil,AuthError(@"登录状态已变更，请重试。"));return;}
    if(accountError){weak.web=nil;completion(nil,accountError);return;}
    NSString *uid=[account[@"uid"] isKindOfClass:NSString.class]?account[@"uid"]:@"";if(!uid.length){weak.web=nil;completion(nil,AuthError(@"服务商未返回账户信息，请重新登录。"));return;}
    NSMutableDictionary *final=[record mutableCopy];final[@"uid"]=uid;
    NSString *nickname=[account[@"nickname"] isKindOfClass:NSString.class]?account[@"nickname"]:@"",*phone=[account[@"phoneNumber"] isKindOfClass:NSString.class]?account[@"phoneNumber"]:@"";
    final[@"accountName"]=nickname.length?nickname:(phone.length?phone:uid);
    NSString *enterprise=[account[@"enterpriseId"] isKindOfClass:NSString.class]?account[@"enterpriseId"]:@"";if(enterprise.length)final[@"enterpriseId"]=enterprise;
    if(!SaveToken(identifier,final)){weak.web=nil;completion(nil,AuthError(@"钥匙串保存失败，连接未切换。"));return;}
    [weak.web cancel];weak.web=nil;completion(@{@"authenticated":@YES,@"accountName":final[@"accountName"]},nil);
   }];
  }];
 }];}
- (ASPresentationAnchor)presentationAnchorForWebAuthenticationSession:(ASWebAuthenticationSession *)session{return self.presenter.view.window;}
- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task willPerformHTTPRedirection:(NSHTTPURLResponse *)response newRequest:(NSURLRequest *)request completionHandler:(void (^)(NSURLRequest *))completionHandler{completionHandler(nil);}
- (void)request:(NSString *)url fields:(NSDictionary *)fields json:(BOOL)json completion:(void(^)(NSDictionary *,NSError *))completion{
 NSMutableURLRequest *r=[NSMutableURLRequest requestWithURL:[NSURL URLWithString:url]];r.HTTPMethod=@"POST";r.timeoutInterval=45;r.HTTPBody=json?[NSJSONSerialization dataWithJSONObject:fields options:0 error:nil]:Form(fields);[r setValue:json?@"application/json":@"application/x-www-form-urlencoded" forHTTPHeaderField:@"Content-Type"];
 NSURLSessionConfiguration *config=NSURLSessionConfiguration.ephemeralSessionConfiguration;config.URLCache=nil;config.HTTPCookieStorage=nil;config.HTTPShouldSetCookies=NO;NSURLSession *s=[NSURLSession sessionWithConfiguration:config delegate:self delegateQueue:NSOperationQueue.mainQueue];
 [[s dataTaskWithRequest:r completionHandler:^(NSData *d,NSURLResponse *response,NSError *error){NSInteger status=[(NSHTTPURLResponse *)response statusCode];NSDictionary *value=d.length<1024*1024?[NSJSONSerialization JSONObjectWithData:d?:NSData.data options:0 error:nil]:nil;dispatch_async(dispatch_get_main_queue(),^{BOOL ok=!error&&status>=200&&status<300;completion([value isKindOfClass:NSDictionary.class]?value:@{},ok?nil:AuthError(@"官方授权请求失败，请重新登录；令牌与响应详情未写入诊断。"));[s finishTasksAndInvalidate];});}] resume];
}
- (void)login:(NSDictionary *)c presenter:(UIViewController *)presenter completion:(TFAIResult)completion{
 if(!NSThread.isMainThread){dispatch_async(dispatch_get_main_queue(),^{[self login:c presenter:presenter completion:completion];});return;}
 NSDictionary *oauth=TFAIProvider(c[@"protocol"])[@"oauth"];if(!oauth){completion(nil,AuthError(@"此服务商本期使用官方 API 密钥。"));return;}
 if([oauth[@"kind"] isEqual:@"workbuddy"]){[self loginWorkBuddy:c oauth:oauth presenter:presenter completion:completion];return;}
 NSURL *base=[NSURL URLWithString:c[@"baseURL"]],*official=[NSURL URLWithString:TFAIProvider(c[@"protocol"])[@"baseURL"]];if(!OfficialBase(base,official)){completion(nil,AuthError(@"OAuth 仅用于该服务商官方 HTTPS 地址。"));return;}
 if(self.web){completion(nil,AuthError(@"已有登录流程正在进行。"));return;}
 NSString *identifier=c[@"id"],*verifier=Random(),*state=Random(),*kind=oauth[@"kind"],*client=c[@"oauthClientID"]?:@"";BOOL google=[kind isEqual:@"google"];
 if(!verifier||!state){completion(nil,AuthError(@"系统随机数生成失败，请重试。"));return;}
 NSString *scheme=@"dylix",*redirect=nil;if(google){if(![client hasSuffix:@".apps.googleusercontent.com"]||[client rangeOfCharacterFromSet:[NSCharacterSet characterSetWithCharactersInString:@"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._"].invertedSet].location!=NSNotFound){completion(nil,AuthError(@"请填写为本App Bundle ID配置的Google iOS OAuth客户端ID。"));return;}scheme=[@"com.googleusercontent.apps." stringByAppendingString:[client substringToIndex:client.length-@".apps.googleusercontent.com".length]];redirect=[scheme stringByAppendingString:@":/oauthredirect"];}else redirect=[NSString stringWithFormat:@"dylix://oauth/openrouter?state=%@",state];
 uint8_t digest[CC_SHA256_DIGEST_LENGTH];NSData *v=[verifier dataUsingEncoding:NSUTF8StringEncoding];CC_SHA256(v.bytes,(CC_LONG)v.length,digest);NSString *challenge=B64([NSData dataWithBytes:digest length:sizeof(digest)]);
 NSURLComponents *parts=[NSURLComponents componentsWithString:oauth[@"authorizationURL"]];NSMutableArray *query=[NSMutableArray arrayWithArray:@[[NSURLQueryItem queryItemWithName:@"code_challenge" value:challenge],[NSURLQueryItem queryItemWithName:@"code_challenge_method" value:@"S256"]]];
 if(google)[query addObjectsFromArray:@[[NSURLQueryItem queryItemWithName:@"client_id" value:client],[NSURLQueryItem queryItemWithName:@"redirect_uri" value:redirect],[NSURLQueryItem queryItemWithName:@"response_type" value:@"code"],[NSURLQueryItem queryItemWithName:@"scope" value:oauth[@"scope"]],[NSURLQueryItem queryItemWithName:@"state" value:state],[NSURLQueryItem queryItemWithName:@"access_type" value:@"offline"],[NSURLQueryItem queryItemWithName:@"prompt" value:@"consent"]]];else[query addObject:[NSURLQueryItem queryItemWithName:@"callback_url" value:redirect]];parts.queryItems=query;
 self.epochs[identifier]=@([self.epochs[identifier] unsignedIntegerValue]+1);self.presenter=presenter;NSUInteger loginSerial=++self.loginSerial;NSUInteger epoch=[self.epochs[identifier] unsignedIntegerValue];__weak typeof(self) weak=self;
 self.web=[[ASWebAuthenticationSession alloc]initWithURL:parts.URL callbackURLScheme:scheme completionHandler:^(NSURL *callback,NSError *error){dispatch_async(dispatch_get_main_queue(),^{TFAIOAuth *s=weak;if(!s)return;if(loginSerial!=s.loginSerial){completion(nil,AuthError(@"登录状态已变更，请重试。"));return;}s.web=nil;NSURLComponents *result=[NSURLComponents componentsWithURL:callback resolvingAgainstBaseURL:NO];NSMutableDictionary *values=[NSMutableDictionary new];BOOL duplicate=NO;for(NSURLQueryItem *q in result.queryItems){if(values[q.name])duplicate=YES;values[q.name]=q.value?:@"";}NSURL *expected=[NSURL URLWithString:redirect];BOOL path=[callback.scheme isEqual:expected.scheme]&&[(callback.host?:@"") isEqual:expected.host?:@""]&&[(callback.path?:@"") isEqual:expected.path?:@""];
 if(error||callback.fragment.length||!path||duplicate||![values[@"state"] isEqual:state]||![values[@"code"] length]||epoch!=[s.epochs[identifier] unsignedIntegerValue]){completion(nil,AuthError(@"登录已取消或授权回调校验失败，原连接保持不变。"));return;}
 NSDictionary *fields=google?@{@"grant_type":@"authorization_code",@"client_id":client,@"code":values[@"code"],@"code_verifier":verifier,@"redirect_uri":redirect}:@{@"code":values[@"code"],@"code_verifier":verifier,@"code_challenge_method":@"S256"};
 [s request:oauth[@"tokenURL"] fields:fields json:!google completion:^(NSDictionary *result,NSError *failure){if(epoch!=[s.epochs[identifier] unsignedIntegerValue]){completion(nil,AuthError(@"登录状态已变更，请重试。"));return;}NSString *access=result[google?@"access_token":@"key"];if(failure||![access isKindOfClass:NSString.class]||!access.length){completion(nil,failure?:AuthError(@"官方授权未返回凭据，请重新登录。"));return;}NSDictionary *record=@{@"accessToken":access,@"refreshToken":[result[@"refresh_token"] isKindOfClass:NSString.class]?result[@"refresh_token"]:@"",@"expiresAt":google?@(NSDate.date.timeIntervalSince1970+MAX(0,[result[@"expires_in"] doubleValue])):@0,@"kind":kind,@"clientID":client};if(!SaveToken(identifier,record)){completion(nil,AuthError(@"钥匙串保存失败，连接未切换。"));return;}completion(@{@"authenticated":@YES},nil);}];});}];self.web.presentationContextProvider=self;self.web.prefersEphemeralWebBrowserSession=YES;if(![self.web start]){self.web=nil;completion(nil,AuthError(@"系统登录页面启动失败，请重试。"));}
}
- (void)credential:(NSDictionary *)c completion:(void(^)(NSString *,NSError *))completion{
 if(!NSThread.isMainThread){dispatch_async(dispatch_get_main_queue(),^{[self credential:c completion:completion];});return;}
 NSString *identifier=c[@"id"]?:@"";NSDictionary *oauth=TFAIProvider(c[@"protocol"])[@"oauth"],*record=ReadToken(identifier);NSURL *url=[NSURL URLWithString:c[@"baseURL"]],*official=[NSURL URLWithString:TFAIProvider(c[@"protocol"])[@"baseURL"]];if(!oauth||!OfficialBase(url,official)){completion(nil,AuthError(@"OAuth 连接地址已变化，请恢复官方地址并重新登录。"));return;}
 if(![record[@"accessToken"] length]){completion(nil,AuthError(@"请先登录此连接。"));return;}
 if(![record[@"kind"] isEqual:oauth[@"kind"]]||([oauth[@"kind"] isEqual:@"google"]&&![record[@"clientID"] isEqual:c[@"oauthClientID"]])){completion(nil,AuthError(@"服务商或OAuth客户端已变化，请退出旧授权后重新登录。"));return;}
 if(![record[@"expiresAt"] doubleValue]||[record[@"expiresAt"] doubleValue]>NSDate.date.timeIntervalSince1970+60){completion(record[@"accessToken"],nil);return;}
 if(self.waiters[identifier]){[self.waiters[identifier] addObject:[completion copy]];return;}self.waiters[identifier]=[NSMutableArray arrayWithObject:[completion copy]];NSUInteger epoch=[self.epochs[identifier] unsignedIntegerValue];
 NSMutableArray *flight=self.waiters[identifier];void (^finish)(NSString *,NSError *)=^(NSString *token,NSError *failure){if(self.waiters[identifier]!=flight)return;NSArray *waiting=[flight copy];[self.waiters removeObjectForKey:identifier];for(void(^cb)(NSString *,NSError *) in waiting)cb(token,failure);};
 if(![record[@"refreshToken"] length]){finish(nil,AuthError(@"授权已过期，请重新登录。"));return;}
 if([record[@"kind"] isEqual:@"workbuddy"]){[self refreshWorkBuddy:c record:record finish:finish];return;}
 [self request:oauth[@"tokenURL"] fields:@{@"grant_type":@"refresh_token",@"refresh_token":record[@"refreshToken"],@"client_id":record[@"clientID"]} json:NO completion:^(NSDictionary *result,NSError *error){if(epoch!=[self.epochs[identifier] unsignedIntegerValue]){finish(nil,AuthError(@"已退出登录。"));return;}if(error||![result[@"access_token"] isKindOfClass:NSString.class]||![result[@"access_token"] length]){finish(nil,AuthError(@"授权刷新失败，请重新登录；原凭据保留供重试。"));return;}NSMutableDictionary *next=[record mutableCopy];next[@"accessToken"]=result[@"access_token"];if([result[@"refresh_token"] isKindOfClass:NSString.class])next[@"refreshToken"]=result[@"refresh_token"];next[@"expiresAt"]=@(NSDate.date.timeIntervalSince1970+MAX(0,[result[@"expires_in"] doubleValue]));if(!SaveToken(identifier,next)){finish(nil,AuthError(@"刷新凭据保存失败，请重新登录。"));return;}finish(next[@"accessToken"],nil);}];
}
// WorkBuddy 续期：POST /v2/plugin/auth/token/refresh，refresh token 走
// X-Refresh-Token 头；refresh token 自身过期则本机退出，需重新扫码。
- (void)refreshWorkBuddy:(NSDictionary *)c record:(NSDictionary *)record finish:(void(^)(NSString *,NSError *))finish{
 NSDictionary *site=WorkBuddySite(TFAIProvider(c[@"protocol"])[@"oauth"]);
 long long refreshEnds=[record[@"refreshExpiresAt"] isKindOfClass:NSNumber.class]?[record[@"refreshExpiresAt"] longLongValue]:0;
 if(refreshEnds>0&&(long long)(NSDate.date.timeIntervalSince1970*1000)>=refreshEnds){finish(nil,AuthError(@"此 WorkBuddy 账户已退出登录，请重新登录。"));return;}
 NSMutableDictionary *headers=[WorkBuddyJSONHeaders() mutableCopy];
 headers[@"X-Refresh-Token"]=record[@"refreshToken"]?:@"";
 headers[@"X-Auth-Refresh-Source"]=@"plugin";
 for(NSString *name in @[@"X-Domain",@"X-Enterprise-Id",@"X-Tenant-Id"])if(WorkBuddyAccountHeaders(record,site)[name])headers[name]=WorkBuddyAccountHeaders(record,site)[name];
 [self workBuddyCall:[NSURL URLWithString:[site[@"endpoint"] stringByAppendingString:@"/v2/plugin/auth/token/refresh"]] method:@"POST" headers:headers body:@{} completion:^(NSDictionary *data,NSError *error){
  if(error){finish(nil,AuthError(@"WorkBuddy 凭据刷新失败，请稍后重试；原凭据保留。"));return;}
  NSDictionary *next=WorkBuddyMergeToken(data?:@{},record);
  if(!next){finish(nil,AuthError(@"WorkBuddy 未返回刷新凭据，请重新登录。"));return;}
  if(!SaveToken(c[@"id"],next)){finish(nil,AuthError(@"刷新凭据保存失败，请重新登录。"));return;}
  finish(next[@"accessToken"],nil);
 }];}
- (void)logout:(NSDictionary *)c completion:(TFAIResult)completion{
 if(!NSThread.isMainThread){dispatch_async(dispatch_get_main_queue(),^{[self logout:c completion:completion];});return;}
 NSString *identifier=c[@"id"]?:@"";self.epochs[identifier]=@([self.epochs[identifier] unsignedIntegerValue]+1);NSArray *waiting=[self.waiters[identifier] copy];[self.waiters removeObjectForKey:identifier];for(void(^cb)(NSString *,NSError *) in waiting)cb(nil,AuthError(@"已退出登录。"));self.loginSerial++;[self.web cancel];self.web=nil;NSDictionary *record=ReadToken(identifier),*oauth=TFAIProvider(c[@"protocol"])[@"oauth"];OSStatus deleted=SecItemDelete((__bridge CFDictionaryRef)TokenQuery(identifier));if(deleted!=errSecSuccess&&deleted!=errSecItemNotFound){completion(nil,AuthError(@"钥匙串清除失败，请重试退出。"));return;}
 if([record[@"kind"] isEqual:@"google"])oauth=TFAIProvider(@"gemini")[@"oauth"];else if([record[@"kind"] isEqual:@"openrouter"])oauth=TFAIProvider(@"openrouter")[@"oauth"];NSString *revoke=oauth[@"revokeURL"],*token=[record[@"refreshToken"] length]?record[@"refreshToken"]:record[@"accessToken"];if(!token.length){completion(@{@"cleared":@YES,@"revoked":@YES},nil);return;}if(!revoke.length){completion(@{@"cleared":@YES,@"revoked":@NO,@"message":@"本机凭据已清除。此官方PKCE流程返回API key，请在OpenRouter密钥管理页撤销该key；本流程没有公开的refresh/revoke接口。"},nil);return;}
 [self request:revoke fields:@{@"token":token} json:NO completion:^(NSDictionary *result,NSError *error){completion(@{@"cleared":@YES,@"revoked":@(!error),@"message":error?@"本机已清除；网络吊销未完成，请在Google账户中撤销授权。":@"已清除并吊销官方授权。"},nil);}];
}
@end
