# Building the libraries for mobile wallets on Android and iOS

## Common requirements
The cryptographic library is written in Rust, and therefore the Rust compiler and Cargo is required. These are often packaged with the package manager of your choice, but can also be obtained through https://rustup.rs/

The cargo build tool depends on git to obtain dependencies from crates.io.

Certain dependencies in the crypto library have foreign code requiring a C compiler to be compiled. A compiler such as GCC works.

## Android
### First time setup
First time compiling the code you'll need to install the standard library for all Android architectures. This can be done using
```
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
```

This should be sufficient for modern devices, but others might be worth installing depending on min target device.

You'll also need an extension for the cargo tool to build linking against the Android NDK. 
```
cargo install cargo-ndk
```

Compiling for Android requires the NDK to be available, and having an environment variable set pointing to the location of it. The NDK and SDK can be installed using Android Studio. On my machine this environment variable is set to
```
export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/21.0.6113669
```

### Building
You should now be able to build the libraries using the script `build-android.sh` located in `crypto/mobile_wallet/android`.
```
./build-android.sh
```

This script builds the Rust libraries for the various Android architectures, and copies the libraries into the Android library folder `mobile_wallet_lib` which can be assembled into an AAR archive with gradle. 

## iOS
### First time usage
To build for iOS, XCode must be installed and the license must have been accepted. This is deemed out of scope for this guide, and therefore assumed to be in working order.

First time compiling the code you'll need to install the standard library for the two iOS architectures. This can be done using
```
rustup target add aarch64-apple-ios x86_64-apple-ios
```

This should be sufficient for modern devices, but others might be worth installing depending on min target device.

You'll also need an extension for the cargo tool to build universal libraries for iOS and generate C headers.
```
cargo install cargo-lipo
cargo install cbindgen
```

### Building
You should now be able to build the crypto library. Go to the `crypto/mobile_wallet` folder.

```
cbindgen src/lib.rs -l c > mobile_wallet.h
```
It will output some warnings which can mostly be ignored. We don't want C headers for the JNI methods only used on Android, and the entries are generated correctly for iOS despite missing config.


Now you have the header file required for use from Swift/ObjC. 

You can now execute
```
cargo lipo --release
```

It will proceed to build the static library which can then be found as `target/universal/release/libmobile_wallet.a`