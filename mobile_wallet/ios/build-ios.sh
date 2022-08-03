#!/usr/bin/env bash

set -euxo pipefail

(cd ../ && cargo build --release --target x86_64-apple-ios && \
cargo build --release --target aarch64-apple-ios-sim && \
cargo build --release --target aarch64-apple-ios)

buildDir=$(pwd)/build
headers=${buildDir}/include
rm -fr ${buildDir}

mkdir ${buildDir}
mkdir ${headers}

cp ./module.modulemap ${headers}
cp ../mobile_wallet.h ${headers}

cp ../target/aarch64-apple-ios/release/libmobile_wallet.a ${buildDir}/libmobile_wallet_ios.a
lipo -create ../target/x86_64-apple-ios/release/libmobile_wallet.a ../target/aarch64-apple-ios-sim/release/libmobile_wallet.a -output ${buildDir}/libmobile_wallet_ios_simulator.a

xcodebuild -create-xcframework -library ${buildDir}/libmobile_wallet_ios.a -headers ${headers} \
-library ${buildDir}/libmobile_wallet_ios_simulator.a -headers ${headers} -output ${buildDir}/libmobile_wallet.xcframework
