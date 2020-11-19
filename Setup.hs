import Distribution.PackageDescription
import Distribution.Simple
import Distribution.Simple.LocalBuildInfo
import Distribution.Simple.Setup
import Distribution.Simple.Utils
import Distribution.System
import Distribution.Verbosity
import Control.Monad
import System.Directory
import System.Environment
import Data.Maybe

concordiumLibs :: [String]
concordiumLibs = [ "ecvrf"
                 , "sha_2"
                 , "eddsa_ed25519"
                 , "ffi_helpers"
                 , "id"
                 , "aggregate_sig"
                 , "encrypted_transfers"
                 ]

type WithEnvAndVerbosity = [(String, String)] -> Verbosity -> IO ()

-- |In linux, we will produce two kind of builds:
-- - Static with musl: the rust libraries will only build static artifacts. Intended to be used inside alpine to produce a static binary.
-- - With glibc: Normal compilation. Rust will produce static and dynamic artifacts.
linuxBuild :: Bool -> WithEnvAndVerbosity
linuxBuild True env verbosity = do
  noticeNoWrap verbosity "Static linking."
  rawSystemExitWithEnv verbosity "cargo" ["build", "--release", "--manifest-path", "rust-src/Cargo.toml", "--target", "x86_64-unknown-linux-musl"]
    (("CARGO_NET_GIT_FETCH_WITH_CLI", "true") : ("RUSTFLAGS", "-C target-feature=-crt-static") : env)
  -- as I have not been able to modify the extra-lib-dirs based on the flag assignment, for now we will copy the musl libs onto the normal target libraries
  let copyLib lib = rawSystemExit verbosity "cp" ["rust-src/target/x86_64-unknown-linux-musl/release/lib" ++ lib ++ ".a", "rust-src/target/release"]
  mapM_ copyLib concordiumLibs
linuxBuild False env verbosity = do
  noticeNoWrap verbosity "Dynamic linking."
  rawSystemExitWithEnv verbosity "cargo" ["build", "--release", "--manifest-path", "rust-src/Cargo.toml"] (("CARGO_NET_GIT_FETCH_WITH_CLI", "true") : env)

-- |I honestly have no idea about what we should do on windows.
windowsBuild :: WithEnvAndVerbosity
windowsBuild env verbosity = do
  rawSystemExitWithEnv verbosity "cargo" ["build", "--release", "--manifest-path", "rust-src/Cargo.toml"] (("CARGO_NET_GIT_FETCH_WITH_CLI", "true")  : env)

-- |On Mac, we will delete the dynamic artifacts if we want to create a static binary.
osxBuild :: Bool -> WithEnvAndVerbosity
osxBuild static env verbosity = do
  rawSystemExitWithEnv verbosity "cargo" ["build", "--release", "--manifest-path", "rust-src/Cargo.toml"] (("CARGO_NET_GIT_FETCH_WITH_CLI", "true")  : env)
  when static $ do
      let deleteDynLib lib = rawSystemExit verbosity "rm" ["-f", "rust-src/target/release/lib" ++ lib ++ ".dylib"]
      mapM_ deleteDynLib concordiumLibs

makeRust :: Args -> ConfigFlags -> PackageDescription -> LocalBuildInfo -> IO ()
makeRust _ flags _ lbi = do
    let verbosity = fromFlag $ configVerbosity flags
        staticLinking = Just True == lookupFlagAssignment (mkFlagName "static") (flagAssignment lbi)
        build = case buildOS of
          Windows -> windowsBuild
          OSX -> osxBuild staticLinking
          Linux -> linuxBuild staticLinking
    env <- getEnvironment
    build env verbosity

main = defaultMainWithHooks simpleUserHooks
  {
    postConf = makeRust
  }
