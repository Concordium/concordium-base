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

makeRust :: Args -> ConfigFlags -> IO HookedBuildInfo
makeRust args flags = do
    let verbosity = fromFlag $ configVerbosity flags
    env <- getEnvironment
    rawSystemExitWithEnv verbosity "cargo"
        ["build", "--release", "--manifest-path", "rust-src/Cargo.toml"]
        (("CARGO_NET_GIT_FETCH_WITH_CLI", "true") : env)
    let libs = [
                "ec_vrf_ed25519",
                "sha_2",
                "eddsa_ed25519",
                "ffi_helpers",
                "id",
                "aggregate_sig"
            ]
    _ <- rawSystemExitCode verbosity "mkdir" ["./lib"]
    -- On Windows, copy the static libraries and DLLs. (The DLLs should not be used by the
    -- linker, but seem to be needed sometimes by TemplateHaskell at compile time.)
    -- On other platforms, symlink the shared libraries.
    case buildOS of
        Windows -> do
            let copyLib lib = do
                rawSystemExit verbosity "cp" ["rust-src/target/release/lib" ++ lib ++ ".a", "./lib/"]
                rawSystemExit verbosity "cp" ["rust-src/target/release/" ++ lib ++ ".dll", "./lib/"]
            mapM_ copyLib libs
        OSX -> do
            let copyLib lib = rawSystemExit verbosity "ln" ["-s", "-f", "../rust-src/target/release/lib" ++ lib ++ ".dylib", "./lib/lib" ++ lib ++ ".dylib"]
            mapM_ copyLib libs
        _ -> do
            let copyLib lib = rawSystemExit verbosity "ln" ["-s", "-f", "../rust-src/target/release/lib" ++ lib ++ ".so", "./lib/lib" ++ lib ++ ".so"]
            mapM_ copyLib libs
    return emptyHookedBuildInfo

main = defaultMainWithHooks simpleUserHooks
  {
    preConf = makeRust
  }

