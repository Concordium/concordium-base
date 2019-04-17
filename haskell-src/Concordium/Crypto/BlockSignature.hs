-- abstraction layer for block signatures

module Concordium.Crypto.BlockSignature where

import qualified Concordium.Crypto.Ed25519Signature as Ed25519
import           Concordium.Crypto.Ed25519Signature (ed25519)
import qualified Concordium.Crypto.SignatureScheme as SCH
import           System.Random
import           Data.ByteString


type SignKey = SCH.SignKey
type VerifyKey = SCH.VerifyKey
type KeyPair = SCH.KeyPair
type Signature = SCH.Signature

sign :: KeyPair -> ByteString -> Signature
sign = SCH.sign ed25519

verify :: VerifyKey -> ByteString -> Signature -> Bool 
verify = SCH.verify ed25519

newPrivateKey:: IO SignKey
newPrivateKey = SCH.newPrivateKey ed25519

publicKey :: SignKey -> VerifyKey
publicKey = SCH.publicKey ed25519

schemeId :: SCH.SchemeId
schemeId = SCH.schemeId ed25519




newKeyPair :: IO SCH.KeyPair
newKeyPair = do sk <- newPrivateKey
                let pk = publicKey sk in 
                    return (SCH.KeyPair sk pk)

randomKeyPair :: RandomGen g => g -> (SCH.KeyPair, g)
randomKeyPair = Ed25519.randomKeyPair

