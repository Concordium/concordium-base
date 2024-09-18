import Data.ProtoLens.Setup
import Distribution.PackageDescription
import Distribution.Simple
import Distribution.Simple.LocalBuildInfo
import Distribution.Simple.Setup
import Distribution.Simple.Utils
import Distribution.System
import Distribution.Verbosity
import System.Environment

concordiumLibs :: [(String, [String])]
concordiumLibs =
    [ ("concordium_base", ["--features", "ffi"]),
      ("sha_2", [])
    ]

type WithEnvAndVerbosity = [(String, String)] -> Verbosity -> IO ()

-- | In linux, we will produce two kind of builds:
--  - Static with musl: the rust libraries will only build static artifacts. Intended to be used inside alpine to produce a static binary.
--  - With glibc: Normal compilation. Rust will produce static and dynamic artifacts.
--
--  The first argument chooses whether to build statically with musl or not.
linuxBuild :: Bool -> WithEnvAndVerbosity
linuxBuild True env verbosity = do
    noticeNoWrap verbosity "Static linking."
    -- the target-feature=-crt-static is needed so that C symbols are not included in the generated rust libraries. For more information check https://rust-lang.github.io/rfcs/1721-crt-static.html
    let makeLib lib = do
            let libName = fst lib
                libFeatures = snd lib
            -- the target-feature=-crt-static is needed so that C symbols are not included in the generated rust libraries. For more information check https://rust-lang.github.io/rfcs/1721-crt-static.html
            rawSystemExitWithEnv
                verbosity
                "cargo"
                (["rustc", "--release", "--manifest-path", "rust-src/" ++ libName ++"/Cargo.toml", "--target", "x86_64-unknown-linux-musl", "--crate-type", "staticlib"] ++ libFeatures)
                (("RUSTFLAGS", "-C target-feature=-crt-static") : env)
            let source = "../rust-src/target/x86_64-unknown-linux-musl/release/lib" ++ libName ++ ".a"
                target = "./lib/lib" ++ libName ++ ".a"
            rawSystemExit verbosity "ln" ["-s", "-f", source, target]
            noticeNoWrap verbosity $ "Linked: " ++ target ++ " -> " ++ source
    mapM_ makeLib concordiumLibs
linuxBuild False env verbosity = do
    noticeNoWrap verbosity "Dynamic linking."
    let makeLib lib = do
            let libName = fst lib
                libFeatures = snd lib
            rawSystemExitWithEnv verbosity "cargo" (["rustc", "--release", "--manifest-path", "rust-src/" ++ libName ++"/Cargo.toml", "--crate-type", "cdylib"] ++ libFeatures) env
            notice verbosity "Linking libraries to ./lib"
            let source = "../rust-src/target/release/lib" ++ libName
                target = "./lib/lib" ++ libName
            rawSystemExit verbosity "ln" ["-s", "-f", source ++ ".a", target ++ ".a"]
            rawSystemExit verbosity "ln" ["-s", "-f", source ++ ".so", target ++ ".so"]
            noticeNoWrap verbosity $ "Linked: " ++ target ++ " -> " ++ source
    mapM_ makeLib concordiumLibs

windowsBuild :: WithEnvAndVerbosity
windowsBuild env verbosity = do
    let makeLib lib = do
            let libName = fst lib
                libFeatures = snd lib
            rawSystemExitWithEnv verbosity "cargo" (["rustc", "--release", "--manifest-path", "rust-src/" ++ libName ++"/Cargo.toml", "--crate-type", "cdylib"] ++ libFeatures) env
            notice verbosity "Linking libraries to ./lib"
            rawSystemExit verbosity "cp" ["-u", "rust-src/target/release/lib" ++ libName ++ ".a", "./lib/"]
            rawSystemExit verbosity "cp" ["-u", "rust-src/target/release/" ++ libName ++ ".dll", "./lib/"]
            notice verbosity $ "Copied " ++ libName ++ "."
    mapM_ makeLib concordiumLibs

-- | On Mac, we will delete the dynamic artifacts if we want to create a static binary.
--
--  The flag tells whether we want a static compilation or not.
osxBuild :: Bool -> WithEnvAndVerbosity
osxBuild static env verbosity = do
    let makeLib lib = do
            let libName = fst lib
                libFeatures = snd lib
            if static
                then do
                    rawSystemExitWithEnv verbosity "cargo" (["rustc", "--release", "--manifest-path", "rust-src/" ++ libName ++"/Cargo.toml", "--crate-type", "staticlib"] ++ libFeatures) env
                    notice verbosity "Linking libraries to ./lib"
                    let source = "../rust-src/target/release/lib" ++ libName ++ ".a"
                    let target = "./lib/lib" ++ libName ++ ".a"
                        others = "./lib/lib" ++ libName ++ ".dylib"
                    rawSystemExit verbosity "rm" ["-f", others]
                    rawSystemExit verbosity "ln" ["-s", "-f", source, target]
                    noticeNoWrap verbosity $ "Linked: " ++ target ++ " -> " ++ source
                    noticeNoWrap verbosity $ "Removed: " ++ others
                else do
                    rawSystemExitWithEnv verbosity "cargo" (["rustc", "--release", "--manifest-path", "rust-src/" ++ libName ++"/Cargo.toml", "--crate-type", "cdylib"] ++ libFeatures) env
                    notice verbosity "Linking libraries to ./lib"
                    let source = "../rust-src/target/release/lib" ++ libName ++ ".dylib"
                    let others = "./lib/lib" ++ libName ++ ".a"
                        target = "./lib/lib" ++ libName ++ ".dylib"
                    rawSystemExit verbosity "rm" ["-f", others]
                    rawSystemExit verbosity "ln" ["-s", "-f", source, target]
                    noticeNoWrap verbosity $ "Linked: " ++ target ++ " -> " ++ source
                    noticeNoWrap verbosity $ "Removed: " ++ others
    mapM_ makeLib concordiumLibs

makeRust :: Args -> ConfigFlags -> PackageDescription -> LocalBuildInfo -> IO ()
makeRust _ flags _ lbi = do
    let verbosity = fromFlag $ configVerbosity flags
        staticLinking = Just True == lookupFlagAssignment (mkFlagName "static") (flagAssignment lbi)
        build = case buildOS of
            Windows -> windowsBuild
            OSX -> osxBuild staticLinking
            Linux -> linuxBuild staticLinking
    env <- getEnvironment
    rawSystemExit verbosity "mkdir" ["-p", "./lib"]
    build env verbosity

main =
    defaultMainWithHooks $
        generatingProtos
            "./concordium-grpc-api"
            simpleUserHooks
                { postConf = makeRust
                }
