module Main where

import Test.Hspec

import qualified ConcordiumTests.Common.Version
import qualified ConcordiumTests.Crypto.BlsSignature
import qualified ConcordiumTests.Crypto.Ed25519DlogProofs
import qualified ConcordiumTests.Crypto.Ed25519Signature
import qualified ConcordiumTests.Crypto.EncryptedTransfers
import qualified ConcordiumTests.Crypto.FFIDataTypes
import qualified ConcordiumTests.Crypto.FFIVerify
import qualified ConcordiumTests.Crypto.SHA256
import qualified ConcordiumTests.Crypto.VRF
import qualified ConcordiumTests.Data.Base58Encoding
import qualified ConcordiumTests.ID.Types
import qualified ConcordiumTests.Utils.Encryption
import qualified Genesis.ParametersSpec
import qualified Types.AccountEncryptedAmountSpec
import qualified Types.AddressesSpec
import qualified Types.AmountFraction
import qualified Types.AmountSpec
import qualified Types.ParametersSpec
import qualified Types.PayloadSerializationSpec
import qualified Types.TransactionSerializationSpec
import qualified Types.TransactionSummarySpec
import qualified Types.UpdatesSpec

main :: IO ()
main = hspec $ parallel $ do
    ConcordiumTests.Common.Version.tests
    ConcordiumTests.Crypto.FFIVerify.tests
    ConcordiumTests.Crypto.FFIDataTypes.tests
    ConcordiumTests.Crypto.SHA256.tests
    ConcordiumTests.Crypto.Ed25519Signature.tests
    ConcordiumTests.Crypto.VRF.tests
    ConcordiumTests.Crypto.BlsSignature.tests
    ConcordiumTests.Data.Base58Encoding.tests
    ConcordiumTests.ID.Types.tests
    ConcordiumTests.Crypto.Ed25519DlogProofs.tests
    ConcordiumTests.Crypto.EncryptedTransfers.tests
    ConcordiumTests.Utils.Encryption.tests
    -- NB: The following tests are far from complete. They do not test what
    -- happens when data is corrupt in various ways (number of commmitted values
    -- is incorrect, or similar)
    Types.PayloadSerializationSpec.tests
    Types.TransactionSerializationSpec.tests
    Types.AmountSpec.tests
    Types.UpdatesSpec.tests
    Types.AccountEncryptedAmountSpec.tests
    Types.AmountFraction.tests
    Types.TransactionSummarySpec.tests
    Types.AddressesSpec.tests
    Types.ParametersSpec.tests
    Genesis.ParametersSpec.tests
