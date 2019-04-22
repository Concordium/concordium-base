{-# LANGUAGE RecordWildCards #-}
module TypesPerf.SerializationPerf where

import Criterion
import Criterion.Main
import Criterion.Types

import Data.ByteString.Char8 as BS

import Concordium.Types(Address(..))

import Concordium.Types.Execution

import Concordium.ID.AccountHolder
import Concordium.ID.Types
import qualified  Concordium.Crypto.Ed25519Signature  as S
import Concordium.Crypto.SignatureScheme

import Data.Serialize

setupAcc :: IO BS.ByteString
setupAcc = do
  keypair <- S.newKeyPair
  let acc = createAccount (verifyKey keypair)
  return $ encode (CreateAccount acc)


setupTransfer :: IO BS.ByteString
setupTransfer = do
  keypair <- S.newKeyPair
  let acc = createAccount (verifyKey keypair)
  return $ encode (Transfer (AddressAccount (accountAddress acc)) 88)

deserialize :: String -> ByteString -> Benchmark
deserialize descr ~ser =
    bench descr $ nf (\d -> case decode d of
                                  Right (CreateAccount ACI{..}) -> aci_auxData == BS.pack "aux"
                                  Right (Transfer _ amount) -> amount == 133
                         )
                      ser

deserializeAcc :: Benchmark
deserializeAcc =
  env setupAcc $ deserialize "Account"

deserializeTransfer :: Benchmark
deserializeTransfer =
  env setupTransfer $ deserialize "Transfer"

main :: IO ()
main = defaultMainWith (defaultConfig { timeLimit = 15 }) [
  deserializeAcc,
  deserializeTransfer
  ]
