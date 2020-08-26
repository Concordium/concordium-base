import Distribution.PackageDescription
import Distribution.Simple
import Distribution.Simple.LocalBuildInfo
import Distribution.Simple.Setup
import Distribution.Simple.Utils
import Distribution.System
import System.Directory
import System.Environment
import Data.Maybe
-- copyExtLib :: Args -> CopyFlags -> PackageDescription -> LocalBuildInfo -> IO ()
-- copyExtLib args flags pkg_descr lbi = do
--     let libPref = dynlibdir (configInstallDirs . configFlags $ lbi)
--     let verbosity = fromFlag $ copyVerbosity flags
--     -- rawSystemExit verbosity "cp" ["rust-src/target/release/libec_vrf_ed25519.so",
-- --                                  "rust-src/target/release/libeddsa_ed25519.so",
-- --                                  "rust-src/target/release/libsha_2.so",
-- --                                  libPref]
makeRust :: Args -> ConfigFlags -> PackageDescription -> LocalBuildInfo -> IO ()
makeRust args flags _ lbi = do
    let verbosity = fromFlag $ configVerbosity flags
        forcedStaticLinkingFlag = lookupFlagAssignment (mkFlagName "forced-static-linking") (flagAssignment lbi)
        hasMusl = lookupFlagAssignment (mkFlagName "link-with-musl") (flagAssignment lbi)
    noticeNoWrap verbosity $ "Forced static linking: " ++ maybe "Not set" show forcedStaticLinkingFlag
    noticeNoWrap verbosity $ "Linking aginst Musl: " ++ maybe "Not set" show hasMusl
    env <- getEnvironment
    rawSystemExitWithEnv verbosity "cargo"
        ["build", "--release", "--manifest-path", "rust-src/Cargo.toml"]
        (("CARGO_NET_GIT_FETCH_WITH_CLI", "true") : env)
    -- NB: This list must be updated when new libraries are added to dependencies.
    let libs = [
                "ec_vrf_ed25519",
                "sha_2",
                "eddsa_ed25519",
                "ffi_helpers",
                "id",
                "aggregate_sig",
                "encrypted_transfers"
            ]
    rawSystemExit verbosity "mkdir" ["-p", "./lib"]
    -- On Windows, copy the static libraries and DLLs. (The DLLs should not be used by the
    -- linker, but seem to be needed sometimes by TemplateHaskell at compile time.)
    -- On other platforms, symlink the shared libraries.
    case (buildOS, forcedStaticLinkingFlag, hasMusl) of
        ( Windows, _, _ ) -> do
            let copyLib lib = do
                rawSystemExit verbosity "cp" ["rust-src/target/release/lib" ++ lib ++ ".a", "./lib/"]
                rawSystemExit verbosity "cp" ["rust-src/target/release/" ++ lib ++ ".dll", "./lib/"]
                notice verbosity $ "Copied " ++ lib ++ "."
            notice verbosity "Copying libraries to ./lib"
            mapM_ copyLib libs
        ( OSX, Just False, _ ) -> do
            let copyLib lib = do
                  let source = "../rust-src/target/release/lib" ++ lib ++ ".dylib"
                  let others = "./lib/lib" ++ lib ++ ".a"
                  let target = "./lib/lib" ++ lib ++ ".dylib"
                  rawSystemExit verbosity "rm" ["-f", others]
                  rawSystemExit verbosity "ln" ["-s", "-f", source, target]
                  noticeNoWrap verbosity $ "Linked: " ++ target ++ " -> " ++ source
                  noticeNoWrap verbosity $ "Removed: " ++ others
            notice verbosity "Linking libraries to ./lib"
            mapM_ copyLib libs
        ( OSX, Just True, _ ) -> do
            let copyLib lib = do
                  let source = "../rust-src/target/release/lib" ++ lib ++ ".a"
                  let others = "./lib/lib" ++ lib ++ ".dylib"
                  let target = "./lib/lib" ++ lib ++ ".a"
                  rawSystemExit verbosity "rm" ["-f", others]
                  rawSystemExit verbosity "ln" ["-s", "-f", source, target]
                  noticeNoWrap verbosity $ "Linked: " ++ target ++ " -> " ++ source
                  noticeNoWrap verbosity $ "Removed: " ++ others
            notice verbosity "Linking libraries to ./lib"
            mapM_ copyLib libs
        ( Linux, _, Just True ) -> do
            let copyLib lib = do
                  let source = "../rust-src/target/x86_64-unknown-linux-musl/release/lib" ++ lib ++ ".a"
                  let others = "./lib/lib" ++ lib ++ ".so"
                  let target = "./lib/lib" ++ lib ++ ".a"
                  rawSystemExit verbosity "rm" ["-f", others]
                  rawSystemExit verbosity "ln" ["-s", "-f", source, target]
                  noticeNoWrap verbosity $ "Linked: " ++ target ++ " -> " ++ source
                  noticeNoWrap verbosity $ "Removed: " ++ others
            notice verbosity "Linking libraries to ./lib"
            mapM_ copyLib libs
        ( _, Just False, _ ) -> do
            let copyLib lib = do
                  let source = "../rust-src/target/release/lib" ++ lib ++ ".so"
                  let others = "./lib/lib" ++ lib ++ ".a"
                  let target = "./lib/lib" ++ lib ++ ".so"
                  rawSystemExit verbosity "rm" ["-f", others]
                  rawSystemExit verbosity "ln" ["-s", "-f", source, target]
                  noticeNoWrap verbosity $ "Linked: " ++ target ++ " -> " ++ source
                  noticeNoWrap verbosity $ "Removed: " ++ others
            notice verbosity "Linking libraries to ./lib"
            mapM_ copyLib libs
        ( _, Just True, _ ) -> do
            let copyLib lib = do
                  let source = "../rust-src/target/release/lib" ++ lib ++ ".a"
                  let others = "./lib/lib" ++ lib ++ ".so"
                  let target = "./lib/lib" ++ lib ++ ".a"
                  rawSystemExit verbosity "rm" ["-f", others]
                  rawSystemExit verbosity "ln" ["-s", "-f", source, target]
                  noticeNoWrap verbosity $ "Linked: " ++ target ++ " -> " ++ source
            notice verbosity "Linking libraries to ./lib"
            mapM_ copyLib libs
    return ()

main = defaultMainWithHooks simpleUserHooks
  {
    postConf = makeRust
  }