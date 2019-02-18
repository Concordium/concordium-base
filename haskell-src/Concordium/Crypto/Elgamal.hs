module Concordium.Crypto.Elgamal where
 
import Data.ByteString

newtype PrivateKey = SK ByteString

newtype PublicKey = PK ByteString 

newtype Message = Message ByteString

newtype Cipher = Cipher ByteString

encrypt :: PublicKey -> Message -> Cipher
encrypt = undefined

decrypt :: PrivateKey -> Cipher -> Message
decrypt = undefined

-- | splits the exponent into chucks of the right size
-- and raise the generator to each chunk and encrypt
exponentEncrypt :: Int -> Message -> [Cipher] 
exponentEncrypt = undefined



