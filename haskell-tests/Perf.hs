module Main where

import qualified PerformanceTests.Ed25519Perf as EdPerf
import qualified PerformanceTests.SHA256Perf as SHA256Perf
import qualified PerformanceTests.VerifyCredentialPerf as VCDIPerf

main = VCDIPerf.main
