#!/bin/sh

# go/clangwrap.sh

SDK_PATH=`xcrun --sdk $SDK --show-sdk-path`
CLANG=`xcrun --sdk $SDK --find clang`
MIN_VERSION=10

if [ "$GOARCH" == "amd64" ]; then
    CARCH="x86_64"
elif [ "$GOARCH" == "arm64" ]; then
    CARCH="arm64"
elif [ "$GOARCH" == "arm" ]; then
    CARCH="armv7"
elif [ "$GOARCH" == "386" ]; then
    CARCH="i386"
fi

if [ "$SDK" = "iphoneos" ]; then
 TARGET="$CARCH-apple-ios$MIN_VERSION"
elif [ "$SDK" = "iphonesimulator" ]; then
 TARGET="$CARCH-apple-ios$MIN_VERSION-simulator"
fi

exec $CLANG -arch $CARCH -target $TARGET -isysroot $SDK_PATH "$@"