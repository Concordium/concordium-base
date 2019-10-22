{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ForeignFunctionInterface #-}
module Concordium.ID.Account where

import Concordium.ID.Types
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

import Data.ByteString as BS
import Data.ByteString.Short as BSS

import Concordium.ID.Parameters
import Concordium.ID.IdentityProvider

type CredentialDeploymentInformationBytes = ByteString

foreign import ccall unsafe "verify_cdi_ffi" verifyCDIFFI
               :: Ptr GlobalContext
               -> Ptr IpInfo
               -> Ptr Word8
               -> CSize
               -> IO Int32


verifyCredential :: GlobalContext -> IpInfo -> CredentialDeploymentInformationBytes -> Bool
verifyCredential gc ipInfo cdiBytes = unsafeDupablePerformIO $ do
    res <- withGlobalContext gc $ \gcPtr ->
           withIpInfo ipInfo $ \ipInfoPtr ->
           unsafeUseAsCStringLen cdiBytes $ \(cdiBytesPtr, cdiBytesLen) ->
           -- this use of unsafe is fine since at this point we know the CDI
           -- bytes is a non-empty string, so the pointer cdiBytesPtr will be
           -- non-null
           verifyCDIFFI gcPtr ipInfoPtr (castPtr cdiBytesPtr) (fromIntegral cdiBytesLen)
    return (res == 1)

registrationId :: IO CredentialRegistrationID
registrationId = (random 48) >>= (return . RegIdCred . FBS.fromByteString)

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
