#!/usr/bin/env bash

set -euxo pipefail

min_ver=29

(cd ../ && cargo ndk --target aarch64-linux-android --android-platform ${min_ver} -- build --release && \
cargo ndk --target armv7-linux-androideabi --android-platform ${min_ver} -- build --release && \
cargo ndk --target i686-linux-android --android-platform ${min_ver} -- build --release && \
cargo ndk --target x86_64-linux-android --android-platform ${min_ver} -- build --release )

jniLibs=$(pwd)/mobile_wallet_lib/src/main/jniLibs
rm -rf ${jniLibs}

mkdir ${jniLibs}
mkdir ${jniLibs}/arm64-v8a
mkdir ${jniLibs}/armeabi-v7a
mkdir ${jniLibs}/x86
mkdir ${jniLibs}/x86_64

cp ../target/aarch64-linux-android/release/*.so ${jniLibs}/arm64-v8a/
cp ../target/aarch64-linux-android/release/deps/*.so ${jniLibs}/arm64-v8a/
cp ../target/armv7-linux-androideabi/release/*.so ${jniLibs}/armeabi-v7a/
cp ../target/armv7-linux-androideabi/release/deps/*.so ${jniLibs}/armeabi-v7a/
cp ../target/i686-linux-android/release/*.so ${jniLibs}/x86/
cp ../target/i686-linux-android/release/deps/*.so ${jniLibs}/x86/
cp ../target/x86_64-linux-android/release/*.so ${jniLibs}/x86_64/
cp ../target/x86_64-linux-android/release/deps/*.so ${jniLibs}/x86_64/

