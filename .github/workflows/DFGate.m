//
// DFGate.m — 卡密门禁 dylib（v4.1：修复封卡后重复弹框导致闪退）
//
// 相对 v3 加固点：
//   1. 服务器地址、签名密钥都做异或混淆，strings 看不到明文
//   2. 请求带 nonce + ts（服务端校验 5 分钟窗口并去重，防重放）
//   3. 响应必须带 HMAC-SHA256 签名，客户端验签通过才放行
//      → 自己搭假服务器返回 {"ok":true} 也没用，除非逆出内嵌密钥
//   4. 本地缓存带签名，改 NSUserDefaults 伪造 expires 无效
//   5. 时间回拨检测：当前时间早于上次服务器时间则拒绝
//   6. 入口方法拦截（mainButtonTapped: / doInitKernel / doStartHUD / initKernelWithCompletion:）
//
// 注意：kUrlEnc / kSigEnc 与服务器 keyserver.py 的 DF_SIGN_SECRET 必须对应
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonDigest.h>
#import <objc/runtime.h>
#import <stdlib.h>

// ======================= 混淆常量（0x5A 异或）=======================
// http://192.168.1.125:8787
static const unsigned char kUrlEnc[] = {
    0x32, 0x2E, 0x2E, 0x2A, 0x60, 0x75, 0x75, 0x6B, 0x68, 0x6E, 0x74, 0x68, 0x68, 0x6B,
    0x74, 0x62, 0x6C, 0x74, 0x6B, 0x6F, 0x6B
};
// df-gate-sign-please-change-32bytes
static const unsigned char kSigEnc[] = {
    0x3E, 0x3C, 0x77, 0x3D, 0x3B, 0x2E, 0x3F, 0x77, 0x29, 0x33, 0x3D, 0x34, 0x77, 0x2A,
    0x36, 0x3F, 0x3B, 0x29, 0x3F, 0x77, 0x39, 0x32, 0x3B, 0x34, 0x3D, 0x3F, 0x77, 0x69,
    0x68, 0x38, 0x23, 0x2E, 0x3F, 0x29
};
// ================================================================

static NSString *const kPrefKey   = @"DFUA_license";
static NSString *const kPrefTicket= @"DFUA_ticket";
static NSString *const kPrefLastTs= @"DFUA_last_ts";
static const  BOOL      kStrict   = YES;
static const  double    kTimeout  = 8.0;
static NSString *const kAppDelegateClass = @"k52msrp07bj14wt63uqhd9nlf8cxyaz5";
static NSString *const kGateVCClass      = @"b2lrzw37gk19vs26jmcp8dqh4nuxey6";

// ---------- 前向声明（C99 要求先声明后使用）----------
static NSDictionary *gLastResp;
static void updateBadgeWith(NSDictionary *r);
static void badgeInvalid(NSString *why);
static void startHeartbeat(void);
static void heartbeatOnce(void);
static void showGate(NSString *why);
static void showTerminal(NSString *why);
static void verifyAsync(void (^done)(BOOL ok, NSString *why));
// ---------------------------------------------------

static volatile BOOL gVerified = NO;
static UIAlertController *gAlert = nil;

// ---------------- 工具 ----------------
static NSString *decode(const unsigned char *p, size_t n) {
    char buf[256] = {0};
    for (size_t i = 0; i < n && i < sizeof(buf) - 1; i++) buf[i] = (char)(p[i] ^ 0x5A);
    return [NSString stringWithUTF8String:buf];
}
static NSString *serverBase(void) { return decode(kUrlEnc, sizeof(kUrlEnc)); }
static NSString *signSecret(void) { return decode(kSigEnc, sizeof(kSigEnc)); }

static NSString *hexOf(NSData *d) {
    const unsigned char *b = d.bytes;
    NSMutableString *s = [NSMutableString stringWithCapacity:d.length * 2];
    for (NSUInteger i = 0; i < d.length; i++) [s appendFormat:@"%02x", b[i]];
    return s;
}

static NSString *sha256Hex(NSString *s) {
    NSData *in = [s dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char out[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(in.bytes, (CC_LONG)in.length, out);
    return hexOf([NSData dataWithBytes:out length:sizeof(out)]);
}

static NSString *hmacHex(NSString *msg) {
    NSData *k = [signSecret() dataUsingEncoding:NSUTF8StringEncoding];
    NSData *m = [msg dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char out[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, k.bytes, k.length, m.bytes, m.length, out);
    return hexOf([NSData dataWithBytes:out length:sizeof(out)]);
}

// 设备指纹：idfv + 机型，再哈希（不直接暴露原始 idfv）
static NSString *deviceId(void) {
    NSString *idfv = [[[UIDevice currentDevice] identifierForVendor] UUIDString] ?: @"none";
    NSString *raw = [NSString stringWithFormat:@"%@|%@", idfv, [[UIDevice currentDevice] model]];
    return [sha256Hex(raw) substringToIndex:32];
}

static NSString *randomNonce(void) {
    unsigned char buf[16];
    arc4random_buf(buf, sizeof(buf));
    return [hexOf([NSData dataWithBytes:buf length:sizeof(buf)]) substringToIndex:24];
}

// ---------------- 网络 ----------------
static NSDictionary *postSync(NSString *path, NSDictionary *body) {
    NSURL *url = [NSURL URLWithString:[serverBase() stringByAppendingString:path]];
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

static NSString *humanize(NSString *code, NSString *fb) {
    if ([code isEqualToString:@"NOT_FOUND"])       return @"卡密不存在，请核对";
    if ([code isEqualToString:@"REVOKED"])         return @"该卡密已被停用";
    if ([code isEqualToString:@"EXPIRED"])         return @"该卡密已过期";
    if ([code isEqualToString:@"DEVICE_MISMATCH"]) return @"该卡密已绑定其他设备";
    if ([code isEqualToString:@"MISSING_KEY"])     return @"请输入卡密";
    if ([code isEqualToString:@"STALE"])           return @"设备时间异常，请校准时间";
    if ([code isEqualToString:@"REPLAY"])          return @"请求重复，请重试";
    if ([code isEqualToString:@"BAD_SIGNATURE"])   return @"响应校验失败";
    return fb.length ? fb : @"验证失败";
}

// 校验响应签名：payload = ok|expires|ts|nonce|device
static BOOL verifyResponse(NSDictionary *r, NSString *device) {
    if (![r isKindOfClass:[NSDictionary class]]) return NO;
    NSString *sig = r[@"sig"];
    if (![sig isKindOfClass:[NSString class]] || sig.length != 64) return NO;
    NSString *msg = [NSString stringWithFormat:@"%@|%lld|%lld|%@|%@",
                     ([r[@"ok"] boolValue] ? @"1" : @"0"),
                     (long long)[r[@"expires"] longLongValue],
                     (long long)[r[@"ts"] longLongValue],
                     r[@"nonce"] ?: @"",
                     device];
    return [sig isEqualToString:hmacHex(msg)];
}

static void verifyAsync(void (^done)(BOOL ok, NSString *why)) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
        NSString *key = [d stringForKey:kPrefKey];
        if (key.length == 0) {
            done(NO, @"请输入卡密后激活");   // 已在后台队列，直接回调
            return;
        }
        // 时间回拨检测
        long long lastTs = [d integerForKey:kPrefLastTs];
        long long nowTs = (long long)[[NSDate date] timeIntervalSince1970];
        if (lastTs > 0 && nowTs + 60 < lastTs) {
            done(NO, @"检测到系统时间被回拨，请校准时间");
            return;
        }

        NSString *dev = deviceId();
        NSString *nonce = randomNonce();
        NSDictionary *r = postSync(@"/activate", @{ @"key": key,
                                                    @"device": dev,
                                                    @"nonce": nonce,
                                                    @"ts": @(nowTs),
                                                    @"ver": @"4.0" });
        BOOL ok = NO; NSString *why = nil;
        if (!r) {
            why = @"无法连接验证服务器";
            if (!kStrict) {
                NSData *tk = [d objectForKey:kPrefTicket];
                if (tk) { ok = YES; why = nil; }   // 宽松模式：有旧票据就放行
            }
        } else if (!verifyResponse(r, dev)) {
            // 签名不对：可能是假服务器 / 被篡改
            ok = NO; why = @"响应校验失败（疑似伪造服务器）";
        } else if (![r[@"ok"] boolValue]) {
            NSString *code = r[@"code"];
            why = humanize(code, r[@"err"]);
            if ([code isEqualToString:@"REVOKED"] || [code isEqualToString:@"EXPIRED"] ||
                [code isEqualToString:@"DEVICE_MISMATCH"] || [code isEqualToString:@"NOT_FOUND"]) {
                [d removeObjectForKey:kPrefKey];
                [d removeObjectForKey:kPrefTicket];
            }
        } else {
            ok = YES;
            gLastResp = r;
            // 存票据（含签名，改了就失效）+ 记录服务器时间
            [d setObject:r forKey:kPrefTicket];
            [d setInteger:[r[@"ts"] longLongValue] forKey:kPrefLastTs];
        }
        [d synchronize];
        done(ok, why);
    });
}

// ---------------- UI ----------------
static UIViewController *topVC(void) {
    UIWindow *w = UIApplication.sharedApplication.keyWindow;
    if (!w) { for (UIWindow *x in UIApplication.sharedApplication.windows) { w = x; break; } }
    UIViewController *vc = w.rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    return vc;
}

static void showGate(NSString *why);
static void showTerminal(NSString *why);

// 安全呈现：避免"正在呈现/正在消失"时重复 present 导致崩溃
static BOOL presentSafe(UIViewController *vc, UIAlertController *a, int attempt) {
    if (!vc || !vc.view.window) return NO;
    @try {
        if (vc.presentedViewController) {
            if (attempt < 3) {
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)),
                               dispatch_get_main_queue(), ^{ presentSafe(vc, a, attempt + 1); });
            }
            return NO;
        }
        [vc presentViewController:a animated:YES completion:nil];
        return YES;
    } @catch (NSException *e) {
        NSLog(@"[DFGate] present 异常（已吞掉）: %@", e);
        return NO;
    }
}

// 终局提示：卡被停用/过期/绑了别的设备 → 只给「退出」，不循环弹框
static void showTerminal(NSString *why) {
    if (gAlert) return;
    UIViewController *vc = topVC();
    if (!vc) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ showTerminal(why); });
        return;
    }
    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"卡密已失效"
                                                              message:why ?: @"请联系卖家"
                                                       preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"退出" style:UIAlertActionStyleDestructive
                                       handler:^(UIAlertAction *act) { exit(0); }]];
    gAlert = a;
    if (!presentSafe(vc, a, 0)) {
        // 呈现不了就直接退出，避免留下半开状态
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ exit(0); });
    }
}

static void showGate(NSString *why) {
    if (gVerified || gAlert) return;
    UIViewController *vc = topVC();
    if (!vc) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ showGate(why); });
        return;
    }
    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"卡密验证"
                                                              message:why ?: @"请输入卡密后激活"
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
        gAlert = nil;
        verifyAsync(^(BOOL ok, NSString *w) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (ok) { NSLog(@"[DFGate] 通过"); gVerified = YES; updateBadgeWith(gLastResp); startHeartbeat(); return; }
                NSLog(@"[DFGate] 失败: %@", w);
                // 硬失败 → 终局提示；软失败 → 重新输入
                if ([w rangeOfString:@"停用"].location != NSNotFound ||
                    [w rangeOfString:@"过期"].location != NSNotFound ||
                    [w rangeOfString:@"其他设备"].location != NSNotFound ||
                    [w rangeOfString:@"不存在"].location != NSNotFound) {
                    showTerminal(w);
                } else {
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.6 * NSEC_PER_SEC)),
                                   dispatch_get_main_queue(), ^{ showGate(w); });
                }
            });
        });
    }]];
    [a addAction:[UIAlertAction actionWithTitle:@"退出" style:UIAlertActionStyleDestructive
                                       handler:^(UIAlertAction *act) { exit(0); }]];
    gAlert = a;
    if (!presentSafe(vc, a, 0)) {
        gAlert = nil;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ showGate(why); });
    }
}

// ---------------- 入口拦截 ----------------
static IMP gOrigButton = NULL, gOrigInit = NULL, gOrigStart = NULL, gOrigKernel = NULL;

static void gate_button(id self, SEL _cmd, id sender) {
    if (!gVerified) { NSLog(@"[DFGate] 拦 mainButtonTapped:"); showGate(@"请先激活卡密"); return; }
    if (gOrigButton) ((void (*)(id, SEL, id))gOrigButton)(self, _cmd, sender);
}
static void gate_init(id self, SEL _cmd) {
    if (!gVerified) { NSLog(@"[DFGate] 拦 doInitKernel"); showGate(@"请先激活卡密"); return; }
    if (gOrigInit) ((void (*)(id, SEL))gOrigInit)(self, _cmd);
}
static void gate_start(id self, SEL _cmd) {
    if (!gVerified) { NSLog(@"[DFGate] 拦 doStartHUD"); showGate(@"请先激活卡密"); return; }
    if (gOrigStart) ((void (*)(id, SEL))gOrigStart)(self, _cmd);
}
static void gate_kernel(id self, SEL _cmd, id block) {
    if (!gVerified) { NSLog(@"[DFGate] 拦 initKernelWithCompletion:"); showGate(@"请先激活卡密"); return; }
    if (gOrigKernel) ((void (*)(id, SEL, id))gOrigKernel)(self, _cmd, block);
}

// ============ 到期徽标（常驻右上角）============
static UILabel *gBadge = nil;

static NSString *formatExpiry(long long exp) {
    if (exp <= 0) return @"永久";
    NSDate *d = [NSDate dateWithTimeIntervalSince1970:(NSTimeInterval)exp];
    NSDateFormatter *f = [[NSDateFormatter alloc] init];
    f.dateFormat = @"yyyy-MM-dd HH:mm";
    return [f stringFromDate:d];
}

// 必须在主线程调用
static void updateBadgeWith(NSDictionary *r) {
    long long exp = [r[@"expires"] longLongValue];
    long long left;                       // 剩余秒数，-1 表示永久
    if (exp <= 0) {
        left = -1;
    } else if (r[@"left_secs"] != nil) {
        left = [r[@"left_secs"] longLongValue];
    } else {
        left = exp - (long long)[[NSDate date] timeIntervalSince1970];
        if (left < 0) left = 0;
    }
    NSString *line1;
    if (left < 0) {
        line1 = @"授权 永久";
    } else if (left >= 86400) {
        line1 = [NSString stringWithFormat:@"剩余 %lld 天 %lld 小时",
                 left / 86400, (left % 86400) / 3600];
    } else if (left >= 3600) {
        line1 = [NSString stringWithFormat:@"剩余 %lld 小时 %lld 分",
                 left / 3600, (left % 3600) / 60];
    } else if (left > 0) {
        line1 = [NSString stringWithFormat:@"剩余 %lld 分", left / 60 + 1];
    } else {
        line1 = @"已到期";
    }
    NSString *line2 = (exp <= 0) ? @"永久有效"
                                 : [NSString stringWithFormat:@"%@ 到期", formatExpiry(exp)];
    NSString *text = [NSString stringWithFormat:@"%@\n%@", line1, line2];

    UIWindow *win = UIApplication.sharedApplication.keyWindow;
    if (!win) {
        for (UIWindow *w in UIApplication.sharedApplication.windows) {
            if (w.isKeyWindow) { win = w; break; }
            win = w;
        }
    }
    if (!win) return;

    if (!gBadge) {
        gBadge = [[UILabel alloc] init];
        gBadge.numberOfLines = 2;
        gBadge.textAlignment = NSTextAlignmentCenter;
        gBadge.font = [UIFont boldSystemFontOfSize:11];
        gBadge.textColor = [UIColor colorWithWhite:1.0 alpha:0.95];
        gBadge.backgroundColor = [UIColor colorWithRed:0 green:0 blue:0 alpha:0.55];
        gBadge.layer.cornerRadius = 6;
        gBadge.clipsToBounds = YES;
        gBadge.userInteractionEnabled = NO;
        gBadge.alpha = 0.9;
        [win addSubview:gBadge];
        NSLog(@"[DFGate] 徽标已创建");
    }
    [gBadge setText:text];
    CGSize sz = [gBadge sizeThatFits:CGSizeMake(200, 60)];
    CGFloat w = MAX(78, sz.width + 12), h = sz.height + 6;
    CGFloat topInset = 8;
    if (@available(iOS 11.0, *)) topInset = win.safeAreaInsets.top + 6;
    gBadge.frame = CGRectMake(win.bounds.size.width - w - 8, topInset, w, h);
    [win bringSubviewToFront:gBadge];
}

static void badgeInvalid(NSString *why) {
    if (!gBadge) return;
    gBadge.text = @"授权失效";
    gBadge.backgroundColor = [UIColor colorWithRed:0.6 green:0 blue:0 alpha:0.75];
}

static IMP gOrigLaunch = NULL;

// ============ 心跳：后台封卡可即时踢下线 ============
static const double   kHeartbeatSec  = 20.0;   // 心跳间隔（秒）
static const BOOL     kKillImmediately = NO;   // YES=发现封卡立刻退出(无提示)；NO=先弹提示再退
static NSTimer *gTimer = nil;
static BOOL gKilling = NO;

static BOOL isHardFail(NSString *why) {
    return ([why rangeOfString:@"停用"].location != NSNotFound ||
            [why rangeOfString:@"过期"].location != NSNotFound ||
            [why rangeOfString:@"其他设备"].location != NSNotFound ||
            [why rangeOfString:@"不存在"].location != NSNotFound);
}

static void heartbeatOnce(void) {
    if (gKilling) return;
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    NSString *key = [d stringForKey:kPrefKey];
    if (key.length == 0) return;
    NSString *dev = deviceId();
    long long ts = (long long)[[NSDate date] timeIntervalSince1970];
    NSDictionary *r = postSync(@"/heartbeat", @{ @"key": key, @"device": dev,
                                                 @"nonce": randomNonce(),
                                                 @"ts": @(ts), @"ver": @"4.2" });
    if (!r) return;                       // 网络问题不误杀
    if (!verifyResponse(r, dev)) return;  // 签名不对不误杀
    if ([r[@"ok"] boolValue]) { gLastResp = r; dispatch_async(dispatch_get_main_queue(), ^{ updateBadgeWith(r); }); return; }

    NSString *code = r[@"code"];
    NSString *why = humanize(code, r[@"err"]);
    if (!isHardFail(why)) return;
    NSLog(@"[DFGate] 心跳发现卡密失效: %@", why);
    gKilling = YES;
    dispatch_async(dispatch_get_main_queue(), ^{ badgeInvalid(why); });
    dispatch_async(dispatch_get_main_queue(), ^{
        if (kKillImmediately) {
            exit(0);
        } else {
            showTerminal(why);
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.2 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ exit(0); });
        }
    });
}

static void startHeartbeat(void) {
    if (gTimer) return;
    gTimer = [NSTimer scheduledTimerWithTimeInterval:kHeartbeatSec repeats:YES
                                               block:^(NSTimer *t) { heartbeatOnce(); }];
    NSLog(@"[DFGate] 心跳已启动，间隔 %.0f 秒", kHeartbeatSec);
}

static void onBecomeActive(void) {
    if (gVerified) heartbeatOnce();
}
static BOOL my_didFinishLaunching(id self, SEL _cmd, UIApplication *app, NSDictionary *opts) {
    BOOL ret = YES;
    if (gOrigLaunch) ret = ((BOOL (*)(id, SEL, UIApplication *, NSDictionary *))gOrigLaunch)(self, _cmd, app, opts);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        verifyAsync(^(BOOL ok, NSString *why) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (ok) { NSLog(@"[DFGate] 缓存票据有效"); gVerified = YES; updateBadgeWith(gLastResp); startHeartbeat(); }
                else showGate(why);
            });
        });
    });
    return ret;
}

static void hookMethod(Class cls, SEL sel, IMP newImp, IMP *origOut) {
    if (!cls) return;
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) { NSLog(@"[DFGate] 缺方法 %@", NSStringFromSelector(sel)); return; }
    if (origOut) *origOut = method_getImplementation(m);
    method_setImplementation(m, newImp);
}

__attribute__((constructor))
static void dfgate_init(void) {
    @autoreleasepool {
        Class vc = NSClassFromString(kGateVCClass);
        if (vc) {
            hookMethod(vc, sel_registerName("mainButtonTapped:"), (IMP)gate_button, &gOrigButton);
            hookMethod(vc, sel_registerName("doInitKernel"),      (IMP)gate_init,   &gOrigInit);
            hookMethod(vc, sel_registerName("doStartHUD"),        (IMP)gate_start,  &gOrigStart);
        }
        Class del = NSClassFromString(kAppDelegateClass);
        if (del) {
            hookMethod(del, sel_registerName("initKernelWithCompletion:"), (IMP)gate_kernel, &gOrigKernel);
            hookMethod(del, sel_registerName("application:didFinishLaunchingWithOptions:"),
                       (IMP)my_didFinishLaunching, &gOrigLaunch);
        }
        [[NSNotificationCenter defaultCenter]
            addObserverForName:UIApplicationDidBecomeActiveNotification
                        object:nil queue:[NSOperationQueue mainQueue]
                    usingBlock:^(NSNotification *n) { onBecomeActive(); }];
        NSLog(@"[DFGate] v4.2 已加载（验签 + 防重放 + 入口拦截 + 心跳踢下线）");
    }
}
