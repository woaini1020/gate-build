//
// DFGate.m — 卡密门禁 dylib（配合自建 keyserver 使用）
//
// 作用：注入后，App 启动时先校验卡密（本地缓存 + 服务器激活），
//       未通过则直接终止启动流程（返回 NO），通过才放行。
//
// 编译（二选一）：
//   A. Theos（推荐）
//        $THEOS/makefiles/... 见同目录 Makefile：`make package` 得到 .deb，
//        或 `make` 得到 .obj/DFGate.dylib
//   B. 直接用 Xcode 的 clang（有 macOS + iOS SDK 时）
//        clang -arch arm64 -miphoneos-version-min=15.0 -isysroot $(xcrun --sdk iphoneos --show-sdk-path) \
//              -dynamiclib -framework Foundation -framework UIKit -o DFGate.dylib DFGate.m
//
// 注入（任选，均需重签）：
//   1) 静态：用 insert_dylib / optool 给可执行文件加 LC_LOAD_DYLIB
//      指向 @executable_path/DFGate.dylib，放进 App 根目录，然后 ldid -S 重签
//   2) 越狱：装成 tweak，由 Cydia/Sileo 加载
//
// 配置：改下面 kServerBase / kKeyId / kPrefKey 三个常量即可
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

// ======================= 配置区 =======================
static NSString *const kServerBase = @"http://192.168.1.125:8787";   // 你的 keyserver 地址
static NSString *const kPrefKey    = @"DFUA_license";              // 本地缓存键
static NSString *const kPrefMeta   = @"DFUA_license_meta";         // 到期信息缓存
static const  BOOL      kStrict    = YES;                          // YES=服务器不通就不放行
static const  double    kTimeout   = 8.0;                          // 激活请求超时（秒）
// =====================================================

static BOOL     gVerified = NO;
static NSString *gReason  = nil;

static NSString *deviceId(void) {
    // 优先 identifierForVendor（不需要额外权限）
    NSUUID *u = [[UIDevice currentDevice] identifierForVendor];
    if (u) return [u UUIDString];
    return @"unknown-device";
}

// 同步 POST（用信号量把异步转同步，最多等 kTimeout 秒）
static NSDictionary *postSync(NSString *path, NSDictionary *body) {
    NSURL *url = [NSURL URLWithString:[kServerBase stringByAppendingString:path]];
    if (!url) return nil;
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    req.HTTPMethod = @"POST";
    req.timeoutInterval = kTimeout;
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    req.HTTPBody = [NSJSONSerialization dataWithJSONObject:body options:0 error:nil];

    __block NSDictionary *result = nil;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    NSURLSessionDataTask *t =
    [[NSURLSession sharedSession] dataTaskWithRequest:req
                                   completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
        if (data.length) {
            id obj = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
            if ([obj isKindOfClass:[NSDictionary class]]) result = obj;
        }
        dispatch_semaphore_signal(sem);
    }];
    [t resume];
    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kTimeout * NSEC_PER_SEC)));
    return result;
}

// 校验流程：先本地缓存 → 再服务器激活/校验
static void runVerify(void) {
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    NSString *key = [d stringForKey:kPrefKey];
    if (key.length == 0) { gReason = @"未激活"; return; }

    NSDictionary *r = postSync(@"/activate", @{ @"key": key,
                                                @"device": deviceId(),
                                                @"ver": @"1.0" });
    if (!r) {
        // 服务器不可达
        if (kStrict) { gReason = @"无法连接验证服务器"; return; }
        gVerified = YES;   // 宽松模式：放行，只记录
        return;
    }
    if ([r[@"ok"] boolValue]) {
        gVerified = YES;
        [d setObject:r forKey:kPrefMeta];
        return;
    }
    gReason = r[@"code"] ?: (r[@"err"] ?: @"验证失败");
    // 被停用/过期 → 清本地卡密，强制重新输入
    NSString *code = r[@"code"];
    if ([code isEqualToString:@"REVOKED"] || [code isEqualToString:@"EXPIRED"] ||
        [code isEqualToString:@"DEVICE_MISMATCH"]) {
        [d removeObjectForKey:kPrefKey];
    }
    [d synchronize];
}

// 简单的输入框（在主线程调用）
static void promptKey(dispatch_block_t done) {
    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"卡密验证"
                                                              message:@"请输入卡密（DFUA-XXXX-XXXX-XXXX-XXXX）"
                                                       preferredStyle:UIAlertControllerStyleAlert];
    [a addTextFieldWithConfigurationHandler:^(UITextField *tf) {
        tf.placeholder = @"DFUA-XXXX-XXXX-XXXX-XXXX";
        tf.autocapitalizationType = UITextAutocapitalizationTypeAllCharacters;
        tf.autocorrectionType = UITextAutocorrectionTypeNo;
    }];
    [a addAction:[UIAlertAction actionWithTitle:@"激活" style:UIAlertActionStyleDefault
                                       handler:^(UIAlertAction *act) {
        NSString *k = [a.textFields.firstObject.text stringByTrimmingCharactersInSet:
                       [NSCharacterSet whitespaceAndNewlineCharacterSet]].uppercaseString;
        if (k.length) [[NSUserDefaults standardUserDefaults] setObject:k forKey:kPrefKey];
        [[NSUserDefaults standardUserDefaults] synchronize];
        runVerify();
        if (done) done();
    }]];
    [a addAction:[UIAlertAction actionWithTitle:@"退出" style:UIAlertActionStyleCancel
                                       handler:^(UIAlertAction *act) { if (done) done(); }]];

    UIWindow *win = UIApplication.sharedApplication.keyWindow;
    UIViewController *top = win.rootViewController;
    while (top.presentedViewController) top = top.presentedViewController;
    [top presentViewController:a animated:YES completion:nil];
}

// ============== 拦截主 App 的启动方法 ==============
// AppDelegate 类名是混淆的，这里按名字取；换成你自己的类名亦可
static NSString *const kAppDelegateClass = @"k52msrp07bj14wt63uqhd9nlf8cxyaz5";

static IMP gOrigLaunch = NULL;

static BOOL my_didFinishLaunching(id self, SEL _cmd, UIApplication *app, NSDictionary *opts) {
    runVerify();
    if (!gVerified) {
        // 未通过：弹框让用户输入，输完再决定
        __block BOOL allow = NO;
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        dispatch_async(dispatch_get_main_queue(), ^{
            promptKey(^{
                allow = gVerified;
                dispatch_semaphore_signal(sem);
            });
        });
        dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(120 * NSEC_PER_SEC)));
        if (!allow) {
            NSLog(@"[DFGate] 拦截启动，原因: %@", gReason);
            return NO;      // 直接终止启动
        }
    }
    if (gOrigLaunch) {
        return ((BOOL (*)(id, SEL, UIApplication *, NSDictionary *))gOrigLaunch)(self, _cmd, app, opts);
    }
    return YES;
}

__attribute__((constructor))
static void dfgate_init(void) {
    @autoreleasepool {
        Class cls = NSClassFromString(kAppDelegateClass);
        if (!cls) {
            // 退化：只做校验，不拦启动（便于调试）
            runVerify();
            NSLog(@"[DFGate] 类未找到，仅校验: %@", gVerified ? @"通过" : gReason);
            return;
        }
        SEL sel = sel_registerName("application:didFinishLaunchingWithOptions:");
        Method m = class_getInstanceMethod(cls, sel);
        if (m) {
            gOrigLaunch = method_getImplementation(m);
            method_setImplementation(m, (IMP)my_didFinishLaunching);
            NSLog(@"[DFGate] 已挂钩启动流程");
        }
    }
}

