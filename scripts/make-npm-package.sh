#!/bin/bash

set -euo pipefail

VERSION=$1
shift

if [ -z $VERSION ]; then
    echo "Usage: $0 <version> [<target dir>]" >&2
    exit 13
fi

TARGET_DIR=$1
if [ -z $TARGET_DIR ]; then
    TARGET_DIR=./build/npm-package/
fi

rm -fr $TARGET_DIR 2>/dev/null

mkdir -p $TARGET_DIR

npx hardhat clean
env COMPILE_MODE=production npx hardhat compile

git archive --format tar HEAD README.md contracts/ js/ | tar xv -C $TARGET_DIR
# rm -fR $TARGET_DIR/contracts/mocks/

mkdir $TARGET_DIR/build
cp -r artifacts/contracts $TARGET_DIR/build

BUILD_INFO_JSON=$(find artifacts/build-info -maxdepth 1 -type f -name '*.json' ! -name '*.output.json' -print -quit)
cp "$BUILD_INFO_JSON" "$TARGET_DIR/build/build-info.json"

find $TARGET_DIR -name "*.dbg.json" -delete
sed "s/%%VERSION%%/$VERSION/" npm-package/package.json > "$TARGET_DIR/package.json"
find $TARGET_DIR

echo "

Now you should run:
cd $TARGET_DIR
npm login  # If not done already
npm publish --access public
"
