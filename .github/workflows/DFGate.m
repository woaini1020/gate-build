//
// DFGate.m — 卡密门禁 dylib（v2：不阻塞启动，改用模态框拦截）
//
// v1 的问题：在 application:didFinishLaunching 里用信号量等主线程弹窗 → 死锁 → 白屏 → 被系统杀
// v2 的做法：
//   1. 让 App 正常启动（返回原始返回值）
//   2. 启动后异步校验：本地有卡密就请求服务器
//   3. 校验不通过 → 弹一个只有「激活/退出」的模态框，盖住界面；不激活就用不了
//   4. 点退出 = exit(0)
//
// 编译/注入见同目录 README
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

// ======================= 配置区 =======================
static NSString *const kServerBase = @"http://192.168.1.125:8787";
static NSString *const kPrefKey    = @"DFUA_license";
static const  BOOL      kStrict    = YES;    // YES=服务器不通也不放行
static const  double    kTimeout   = 8.0;
static NSString *const kAppDelegateClass = @"k52msrp07bj14wt63uqhd9nlf8cxyaz5";
// =====================================================

static UIAlertController *gAlert = nil;
static BOOL gBusy = NO;

static NSString *deviceId(void) {
    NSUUID *u = [[UIDevice currentDevice] identifierForVendor];
    return u ? [u UUIDString] : @"unknown-device";
}

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
    [[[NSURLSession sharedSession] dataTaskWithRequest:req
                                   completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
        if (d.length) {
            id o = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
            if ([o isKindOfClass:[NSDictionary class]]) result = o;
        }
        dispatch_semaphore_signal(sem);
    }] resume];
    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kTimeout * NSEC_PER_SEC)));
    return result;
}

static UIViewController *topVC(void) {
    UIWindow *w = UIApplication.sharedApplication.keyWindow;
    if (!w) {
        for (UIWindow *x in UIApplication.sharedApplication.windows) { w = x; break; }
    }
    UIViewController *vc = w.rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    return vc;
}

static void verifyAsync(void (^done)(BOOL ok, NSString *why)) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
        NSString *key = [d stringForKey:kPrefKey];
        if (key.length == 0) {
            dispatch_async(dispatch_get_main_queue(), ^{ done(NO, @"未激活，请输入卡密"); });
            return;
        }
        NSDictionary *r = postSync(@"/activate", @{ @"key": key,
                                                    @"device": deviceId(),
                                                    @"ver": @"2.0" });
        BOOL ok = (r && [r[@"ok"] boolValue]);
        NSString *why = nil;
        if (!r) why = @"无法连接验证服务器";
        else if (!ok) why = r[@"code"] ?: (r[@"err"] ?: @"验证失败");
        NSString *code = r[@"code"];
        if ([code isEqualToString:@"REVOKED"] || [code isEqualToString:@"EXPIRED"] ||
            [code isEqualToString:@"DEVICE_MISMATCH"]) {
            [d removeObjectForKey:kPrefKey];
            [d synchronize];
        }
        dispatch_async(dispatch_get_main_queue(), ^{ done(ok, why); });
    });
}

// 弹出拦截框（只允许「激活」或「退出」）
static void showGate(NSString *why) {
    if (gAlert || gBusy) return;
    UIViewController *vc = topVC();
    if (!vc) {
        // 界面还没起来，稍后重试
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.8 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ showGate(why); });
        return;
    }

    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"卡密验证"
                                                              message:why ?: @"请输入卡密"
                                                       preferredStyle:UIAlertControllerStyleAlert];
    [a addTextFieldWithConfigurationHandler:^(UITextField *tf) {
        tf.placeholder = @"DFUA-XXXX-XXXX-XXXX-XXXX";
        tf.autocapitalizationType = UITextAutocapitalizationTypeAllCharacters;
        tf.autocorrectionType = UITextAutocorrectionTypeNo;
    }];
    __weak UIAlertController *weakA = a;
    [a addAction:[UIAlertAction actionWithTitle:@"激活" style:UIAlertActionStyleDefault
                                       handler:^(UIAlertAction *act) {
        NSString *k = [weakA.textFields.firstObject.text stringByTrimmingCharactersInSet:
                       [NSCharacterSet whitespaceAndNewlineCharacterSet]].uppercaseString;
        if (k.length) {
            [[NSUserDefaults standardUserDefaults] setObject:k forKey:kPrefKey];
            [[NSUserDefaults standardUserDefaults] synchronize];
        }
        gBusy = YES;
        verifyAsync(^(BOOL ok, NSString *w) {
            gBusy = NO;
            if (ok) {
                NSLog(@"[DFGate] 验证通过");
                gAlert = nil;
                return;
            }
            NSLog(@"[DFGate] 验证失败: %@", w);
            gAlert = nil;
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.2 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ showGate(w); });
        });
    }]];
    [a addAction:[UIAlertAction actionWithTitle:@"退出" style:UIAlertActionStyleDestructive
                                       handler:^(UIAlertAction *act) {
        NSLog(@"[DFGate] 用户退出");
        exit(0);
    }]];
    // 禁止点击遮罩关闭
    a.modalInPopover = YES;

    gAlert = a;
    [vc presentViewController:a animated:YES completion:nil];
    NSLog(@"[DFGate] 已弹出卡密拦截框: %@", why);
}

// ============ 挂钩：启动后异步校验，不阻塞 ============
static IMP gOrigLaunch = NULL;

static BOOL my_didFinishLaunching(id self, SEL _cmd, UIApplication *app, NSDictionary *opts) {
    BOOL ret = YES;
    if (gOrigLaunch) {
        ret = ((BOOL (*)(id, SEL, UIApplication *, NSDictionary *))gOrigLaunch)(self, _cmd, app, opts);
    }
    // 界面起来后再校验
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.6 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        verifyAsync(^(BOOL ok, NSString *why) {
            if (ok) {
                NSLog(@"[DFGate] 缓存卡密有效，放行");
            } else {
                showGate(why);
            }
        });
    });
    return ret;
}

__attribute__((constructor))
static void dfgate_init(void) {
    @autoreleasepool {
        Class cls = NSClassFromString(kAppDelegateClass);
        if (!cls) {
            NSLog(@"[DFGate] 未找到 AppDelegate 类，门禁未生效");
            return;
        }
        SEL sel = sel_registerName("application:didFinishLaunchingWithOptions:");
        Method m = class_getInstanceMethod(cls, sel);
        if (!m) {
            NSLog(@"[DFGate] 未找到启动方法，门禁未生效");
            return;
        }
        gOrigLaunch = method_getImplementation(m);
        method_setImplementation(m, (IMP)my_didFinishLaunching);
        NSLog(@"[DFGate] 门禁已挂钩");
    }
}
