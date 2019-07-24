{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ForeignFunctionInterface #-}
module Concordium.ID.Account where

import Concordium.ID.Types
import Concordium.Crypto.FFIDataTypes
import GHC.Word
import Data.ByteString.Random.MWC
import Concordium.Crypto.SignatureScheme
import qualified Concordium.Crypto.SHA224 as SHA224
import qualified Data.ByteString as BS
import qualified Data.FixedByteString as FBS
import System.IO.Unsafe
import Foreign.Ptr
import Foreign.C.Types
import Data.Int
import Data.ByteString.Unsafe

import Data.Base58String.Bitcoin

import Data.ByteString as BS
import Data.ByteString.Short as BSS

type CredentialDeploymentInformationBytes = ByteString

foreign import ccall unsafe "verify_cdi_ffi" verifyCDIFFI
               :: Ptr ElgamalGen
               -> Ptr PedersenKey
               -> Ptr PsSigKey
               -> Ptr ElgamalGen
               -> Ptr ElgamalPublicKey
               -> Ptr Word8
               -> CSize
               -> IO Int32


verifyCredential :: ElgamalGen -> PedersenKey -> IdentityProviderPublicKey -> ElgamalGen -> AnonymityRevokerPublicKey -> CredentialDeploymentInformationBytes -> Bool
verifyCredential elgamalGen pedersenKey (IP_PK idPK) arElgamalGenerator (AnonymityRevokerPublicKey anonPK) cdiBytes = unsafeDupablePerformIO $ do
    res <- withElgamalGen elgamalGen $
           \elgamalGenPtr ->withPedersenKey pedersenKey $
           \pedersenKeyPtr -> withElgamalGen arElgamalGenerator $
           \elgamalGeneratorPtr -> withElgamalPublicKey anonPK $
           \anonPKPtr -> withPsSigKey idPK $
           \ipVerifyKeyPtr -> unsafeUseAsCStringLen cdiBytes $
           \(cdiBytesPtr, cdiBytesLen) -> verifyCDIFFI elgamalGenPtr pedersenKeyPtr ipVerifyKeyPtr elgamalGeneratorPtr anonPKPtr (castPtr cdiBytesPtr) (fromIntegral cdiBytesLen)
    return (res == 1)


registrationId :: IO CredentialRegistrationID
registrationId = (random 48) >>= (return . RegIdCred . FBS.fromByteString)

base58decodeAddr :: Base58String -> AccountAddress
base58decodeAddr bs = AccountAddress (FBS.fromByteString (toBytes bs))

accountScheme :: AccountAddress -> Maybe SchemeId
accountScheme (AccountAddress s) = toScheme (FBS.getByte s 0)


-- |Compute the account address from account's (public) verification key and the signature scheme identifier.
-- The address is computed by the following algorithm
--
--  * compute SHA-224 hash of the verification key
--  * take the first 20 bytes of the resulting string
--  * and prepend a one byte identifier of the signature scheme.
accountAddress :: AccountVerificationKey -> SchemeId -> AccountAddress 
accountAddress (VerifyKey x) y =  AccountAddress (FBS.fromByteString $ BS.cons sch (BS.take (accountAddressSize - 1) bs))
    where 
        (SHA224.Hash r) = SHA224.hash (BSS.fromShort x)
        bs = FBS.toByteString r
        sch:: Word8
        sch = fromIntegral $ fromEnum y
