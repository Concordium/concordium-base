import Distribution.PackageDescription
import Distribution.Simple
import Distribution.Simple.LocalBuildInfo
import Distribution.Simple.Setup
import Distribution.Simple.Utils
import Distribution.System
import Distribution.Verbosity
import System.Environment

concordiumLibs :: [String]
concordiumLibs =
    [ "ecvrf",
      "sha_2",
      "eddsa_ed25519",
      "ffi_helpers",
      "id",
      "aggregate_sig",
      "encrypted_transfers"
    ]

type WithEnvAndVerbosity = [(String, String)] -> Verbosity -> IO ()

-- |In linux, we will produce two kind of builds:
-- - Static with musl: the rust libraries will only build static artifacts. Intended to be used inside alpine to produce a static binary.
-- - With glibc: Normal compilation. Rust will produce static and dynamic artifacts.
--
-- The first argument chooses whether to build statically with musl or not.
linuxBuild :: Bool -> WithEnvAndVerbosity
linuxBuild True env verbosity = do
    noticeNoWrap verbosity "Static linking."
    -- the target-feature=-crt-static is needed so that C symbols are not included in the generated rust libraries. For more information check https://rust-lang.github.io/rfcs/1721-crt-static.html
    rawSystemExitWithEnv
        verbosity
        "cargo"
        ["build", "--release", "--manifest-path", "rust-src/Cargo.toml", "--target", "x86_64-unknown-linux-musl"]
        (("RUSTFLAGS", "-C target-feature=-crt-static") : env)
    let copyLib lib = do
            let source = "../rust-src/target/x86_64-unknown-linux-musl/release/lib" ++ lib ++ ".a"
                target = "./lib/lib" ++ lib ++ ".a"
            rawSystemExit verbosity "ln" ["-s", "-f", source, target]
            noticeNoWrap verbosity $ "Linked: " ++ target ++ " -> " ++ source
    mapM_ copyLib concordiumLibs
linuxBuild False env verbosity = do
    noticeNoWrap verbosity "Dynamic linking."
    rawSystemExitWithEnv verbosity "cargo" ["build", "--release", "--manifest-path", "rust-src/Cargo.toml"] env
    let copyLib lib = do
            let source = "../rust-src/target/release/lib" ++ lib
                target = "./lib/lib" ++ lib
            rawSystemExit verbosity "ln" ["-s", "-f", source ++ ".a", target ++ ".a"]
            rawSystemExit verbosity "ln" ["-s", "-f", source ++ ".so", target ++ ".so"]
            noticeNoWrap verbosity $ "Linked: " ++ target ++ " -> " ++ source
    notice verbosity "Linking libraries to ./lib"
    mapM_ copyLib concordiumLibs

windowsBuild :: WithEnvAndVerbosity
windowsBuild env verbosity = do
    let copyLib lib = do
            rawSystemExit verbosity "cp" ["-u", "rust-src/target/release/lib" ++ lib ++ ".a", "./lib/"]
            rawSystemExit verbosity "cp" ["-u", "rust-src/target/release/" ++ lib ++ ".dll", "./lib/"]
            notice verbosity $ "Copied " ++ lib ++ "."
    rawSystemExitWithEnv verbosity "cargo" ["build", "--release", "--manifest-path", "rust-src/Cargo.toml"] env
    notice verbosity "Copying libraries to ./lib"
    mapM_ copyLib concordiumLibs

-- |On Mac, we will delete the dynamic artifacts if we want to create a static binary.
--
-- The flag tells whether we want a static compilation or not.
osxBuild :: Bool -> WithEnvAndVerbosity
osxBuild static env verbosity = do
    let copyLib lib = do
            if static
                then do
                    let source = "../rust-src/target/release/lib" ++ lib ++ ".a"
                    let target = "./lib/lib" ++ lib ++ ".a"
                        others = "./lib/lib" ++ lib ++ ".dylib"
                    rawSystemExit verbosity "rm" ["-f", others]
                    rawSystemExit verbosity "ln" ["-s", "-f", source, target]
                    noticeNoWrap verbosity $ "Linked: " ++ target ++ " -> " ++ source
                    noticeNoWrap verbosity $ "Removed: " ++ others
                else do
                    let source = "../rust-src/target/release/lib" ++ lib ++ ".dylib"
                    let others = "./lib/lib" ++ lib ++ ".a"
                        target = "./lib/lib" ++ lib ++ ".dylib"
                    rawSystemExit verbosity "rm" ["-f", others]
                    rawSystemExit verbosity "ln" ["-s", "-f", source, target]
                    noticeNoWrap verbosity $ "Linked: " ++ target ++ " -> " ++ source
                    noticeNoWrap verbosity $ "Removed: " ++ others
    rawSystemExitWithEnv verbosity "cargo" ["build", "--release", "--manifest-path", "rust-src/Cargo.toml"] env
    notice verbosity "Linking libraries to ./lib"
    mapM_ copyLib concordiumLibs

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
    defaultMainWithHooks
        simpleUserHooks
            { postConf = makeRust
            }
