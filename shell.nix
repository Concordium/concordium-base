let
  moz_overlay = import (builtins.fetchTarball
    "https://github.com/mozilla/nixpkgs-mozilla/archive/master.tar.gz");
  pkgs_overlay = (self: super: {
    flatbuffers = super.flatbuffers.overrideDerivation (old: {
      pname = "flatbuffers";
      version = "1.11.0";
      name = "flatbuffers-1.11.0";
      src = super.fetchFromGitHub {
        owner = "google";
        repo = "flatbuffers";
        rev = "v1.11.0";
        sha256 = "1gl8pnykzifh7pnnvl80f5prmj5ga60dp44inpv9az2k9zaqx3qr";
      };
    });
  });
  nixpkgs = import <nixpkgs> {
    overlays = [ pkgs_overlay moz_overlay ];
    config = { android_sdk.accept_license = true; };
  };
  rustStableChannel =
    (nixpkgs.rustChannelOf { channel = "1.44.1"; }).rust.override {
      targets = [
        "x86_64-unknown-linux-gnu"
        "wasm32-unknown-unknown"
        "aarch64-linux-android"
        "armv7-linux-androideabi"
        "i686-linux-android"
        "x86_64-linux-android"
      ];
      extensions =
        [ "rust-src" "rls-preview" "clippy-preview" "rustfmt-preview" ];
    };
  androidComposition = nixpkgs.androidenv.composeAndroidPackages {
    abiVersions = [ "armeabi-v7a" "arm64-v8a" "x86" "x86_64" ];
    includeNDK = true;
    ndkVersion = "21.0.6113669";
  };

in with nixpkgs;
stdenv.mkDerivation {
  name = "concordium_shell";
  hardeningDisable = [ "all" ];
  buildInputs = [
    rustStableChannel
    androidComposition.androidsdk
    protobuf
    pkgconfig
    unbound
    numactl
    gmp
    cmake
    curl
    gnutar
    capnproto
    flatbuffers
    wasm-pack
    nodejs
  ];
  ANDROID_SDK_ROOT = "${androidComposition.androidsdk.out}/libexec/android-sdk";
  ANDROID_SDK_HOME = "${androidComposition.androidsdk.out}/libexec/android-sdk";
  ANDROID_NDK_ROOT =
    "${androidComposition.androidsdk.out}/libexec/android-sdk/ndk-bundle";
  ANDROID_NDK_HOME =
    "${androidComposition.androidsdk.out}/libexec/android-sdk/ndk-bundle";
}
