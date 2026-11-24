#!/bin/bash
# Created by yuxilong on 2026/10/27.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$ROOT/.tmp"
WORK="$(mktemp -d "$ROOT/.tmp/libsodium.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

curl --fail --location --output "$WORK/libsodium.tar.gz" \
  https://download.libsodium.org/libsodium/releases/old/libsodium-1.0.18.tar.gz
echo "6f504490b342a4f8a4c4a02fc9b866cbef8622d5df4e5452b46be121e46636c1  $WORK/libsodium.tar.gz" | shasum -a 256 -c -
tar -xzf "$WORK/libsodium.tar.gz" -C "$WORK"
SOURCE="$WORK/libsodium-1.0.18"

# 保持现有 1.0.18 minimal 配置；arm64 真机和模拟器必须分别编译。
for TARGET in arm64-apple-ios15.0 arm64-apple-ios15.0-simulator x86_64-apple-ios15.0-simulator; do
  SDK=iphoneos
  HOST=aarch64-apple-darwin
  if [[ "$TARGET" == *-simulator ]]; then
    SDK=iphonesimulator
  fi
  if [[ "$TARGET" == x86_64-* ]]; then
    HOST=x86_64-apple-darwin
  fi
  mkdir "$WORK/$TARGET"
  (
    cd "$WORK/$TARGET"
    CC="$(xcrun --sdk "$SDK" -f clang)" \
    CFLAGS="-O2 -target $TARGET -isysroot $(xcrun --sdk "$SDK" --show-sdk-path)" \
    LDFLAGS="-target $TARGET -isysroot $(xcrun --sdk "$SDK" --show-sdk-path)" \
      "$SOURCE/configure" --host="$HOST" \
      --disable-shared --enable-minimal --prefix="$WORK/install/$TARGET"
    make -j"$(sysctl -n hw.ncpu)" install
  )
done

mkdir "$WORK/simulator"
xcrun lipo -create \
  "$WORK/install/arm64-apple-ios15.0-simulator/lib/libsodium.a" \
  "$WORK/install/x86_64-apple-ios15.0-simulator/lib/libsodium.a" \
  -output "$WORK/simulator/libsodium.a"
xcodebuild -create-xcframework \
  -library "$WORK/install/arm64-apple-ios15.0/lib/libsodium.a" \
  -library "$WORK/simulator/libsodium.a" \
  -output "$WORK/libsodium.xcframework"

# 成功封装后才替换产物，公开头文件继续使用仓库内的同版本头文件。
rm -rf "$ROOT/SodiumRSAKit/Sodium/libsodium.xcframework"
mv "$WORK/libsodium.xcframework" "$ROOT/SodiumRSAKit/Sodium/"
