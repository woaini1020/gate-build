# DFGate dylib 构建（无需 Theos，纯 clang + ldid）
#
# 用法：
#   make            编译 DFGate.dylib 并（若有 ldid）签名
#   make clean      清理
#
# 依赖：
#   Xcode Command Line Tools（提供 clang 与 iOS SDK）
#   ldid（可选，brew install ldid；没有则用 codesign -s - 做 ad-hoc）

SDK        := $(shell xcrun --sdk iphoneos --show-sdk-path 2>/dev/null)
CC         := $(shell xcrun --sdk iphoneos -f clang 2>/dev/null || echo clang)
MIN_IOS    := 15.0
ARCHS      := arm64
TARGET     := DFGate.dylib
SRC        := DFGate.m

CFLAGS := -arch $(ARCHS) -miphoneos-version-min=$(MIN_IOS) -isysroot $(SDK) \
          -dynamiclib -fobjc-arc -O2 -fvisibility=hidden \
          -framework Foundation -framework UIKit \
          -Wall -Wno-unused-parameter

all: $(TARGET)
	@echo ""
	@echo "构建完成: $(TARGET)"
	@echo "下一步: python3 inject_lc.py --ipa 输入.tipa --dylib $(TARGET) --out 输出.tipa"

$(TARGET): $(SRC)
	@if [ -z "$(SDK)" ]; then echo "!! 找不到 iOS SDK，请在 macOS + Xcode 环境下运行"; exit 1; fi
	$(CC) $(CFLAGS) -o $@ $<
	@if command -v ldid >/dev/null 2>&1; then \
		ldid -S $@ && echo "已用 ldid 做 ad-hoc 签名"; \
	else \
		codesign -s - --force $@ && echo "已用 codesign 做 ad-hoc 签名"; \
	fi

clean:
	rm -f $(TARGET)

.PHONY: all clean

