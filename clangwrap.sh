#!/bin/sh

# go/clangwrap.sh

SDK_PATH=`xcrun --sdk $SDK --show-sdk-path`
CLANG=`xcrun --sdk $SDK --find clang`
IOS_TARGET=10
EXTRA_ARGS=""

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
 EXTRA_ARGS="-fembed-bitcode -miphoneos-version-min==$IOS_TARGET"
 TARGET="$CARCH-apple-ios$IOS_TARGET"
elif [ "$SDK" = "iphonesimulator" ]; then
 EXTRA_ARGS="-fembed-bitcode -mios-simulator-version-min=$IOS_TARGET"
 TARGET="$CARCH-apple-ios$IOS_TARGET-simulator"
elif [ "$SDK" = "macosx" ]; then
 IOS_TARGET=14
 TARGET="$CARCH-apple-ios$IOS_TARGET-macabi"
   if [ "$GOARCH" == "arm64" ]; then
     EXTRA_ARGS="-fembed-bitcode"
   fi
fi

exec $CLANG -target $TARGET $EXTRA_ARGS -isysroot $SDK_PATH "$@"