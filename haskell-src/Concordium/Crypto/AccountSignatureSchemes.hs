module Concordium.Crypto.AccountSignatureSchemes
  (sign
  ,verify
  ,newKeyPair)
where

import qualified Data.ByteString as BS
import Data.Vector as Vec

import qualified Concordium.Crypto.SignatureScheme as Scheme
import Concordium.Crypto.SignatureScheme(SchemeId, KeyPair, Signature, VerifyKey, SignatureScheme)

import Concordium.Crypto.Ed25519Signature(ed25519)

-- |NB: Unsafe here is fine as long as the 'schemes' vector contains all the schemes listed 'SchemeId'
-- inline should be helpful in the case the signature cheme is statically known
{-# INLINE sign #-}
sign :: SchemeId -> KeyPair -> BS.ByteString -> Signature
sign = Scheme.sign . Vec.unsafeIndex schemes . fromEnum

{-# INLINE verify #-}
verify :: SchemeId -> VerifyKey -> BS.ByteString -> Signature -> Bool
verify = Scheme.verify . Vec.unsafeIndex schemes . fromEnum

newKeyPair :: SchemeId -> IO KeyPair
newKeyPair si =
  let sch = Vec.unsafeIndex schemes (fromEnum si)
  in do
    sk <- Scheme.newPrivateKey sch
    let vk = Scheme.publicKey sch sk
    return $ Scheme.KeyPair sk vk

-- |A vector of account signature schemes.
-- NB: The index in the vector must be fromEnum of the SchemeId, hence to and from enum should be 0 indexed.
schemes :: Vector SignatureScheme
schemes = Vec.fromList
          [error "CL scheme not implemented."
          ,ed25519
          ]

