#!/bin/bash

# Determine version and require NAME as an env variable
VERSION=$(git describe --tags --abbrev=0 2>/dev/null || echo "0.0.$(git rev-parse --short HEAD)")
SED_INPLACE_FLAG=("-i")

# Adjust sed for macOS
if [[ "$OSTYPE" == "darwin"* ]]; then
  SED_INPLACE_FLAG=("-i" "")
fi



VERSION=${VERSION#v}
VERSION=$(echo "$VERSION" | sed 's/-.*//')

BUILD_NUMBER=${BUILD_NUMBER:-"${VERSION}.$(date +%s)"}


echo "Using version: $VERSION"
echo "Using build number: $BUILD_NUMBER"

echo "Using name: ${NAME:-<not set>}"
echo "Using header name: ${HEADER_NAME:-<not set>}"

find $1 -type f -name "*.plist" -exec sed "${SED_INPLACE_FLAG[@]}" "s/_VERSION_/${VERSION}/g" {} +
find $1 -type f -name "*.plist" -exec sed "${SED_INPLACE_FLAG[@]}" "s/_BUILD_NUMBER_/${BUILD_NUMBER}/g" {} +

if [[ -n "$HEADER_NAME" ]]; then
  find $1 \( -name "*.modulemap" \) \
    -exec sed "${SED_INPLACE_FLAG[@]}" "s/_HEADER_NAME_/${HEADER_NAME}/g" {} +
  echo "Replaced _HEADER_NAME_ with $HEADER_NAME"
fi

if [[ -n "$NAME" ]]; then
  find $1 \( -name "*.plist" -o -name "*.modulemap" \) \
    -exec sed "${SED_INPLACE_FLAG[@]}" "s/_NAME_/${NAME}/g" {} +
  echo "Replaced _NAME_ with $NAME"
fi

