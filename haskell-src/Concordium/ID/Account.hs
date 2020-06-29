{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ForeignFunctionInterface #-}
module Concordium.ID.Account where

import GHC.Word
import System.IO.Unsafe
import Foreign.Ptr
import Foreign.C.Types
import Data.Int
import Data.ByteString.Unsafe

import Data.ByteString as BS

import Concordium.ID.Types
import Concordium.ID.Parameters
import Concordium.ID.IdentityProvider
import Data.Serialize(encode)

type CredentialDeploymentInformationBytes = ByteString

foreign import ccall unsafe "verify_cdi_ffi" verifyCDIFFI
               :: Ptr GlobalContext
               -> Ptr IpInfo
               -> Ptr Word8
               -> CSize
               -> Ptr Word8
               -> CSize
               -> IO Int32

-- FIXME: We pass in keys as byte arrays which is quite bad since
-- keys are not bytes, but rather we know that they are well-formed already.

verifyCredential :: GlobalContext -> IpInfo -> Maybe AccountKeys -> CredentialDeploymentInformationBytes -> Bool
verifyCredential gc ipInfo Nothing cdiBytes = unsafeDupablePerformIO $ do
    res <- withGlobalContext gc $ \gcPtr ->
            withIpInfo ipInfo $ \ipInfoPtr ->
              unsafeUseAsCStringLen cdiBytes $ \(cdiBytesPtr, cdiBytesLen) -> do
              -- this use of unsafe is fine since at this point we know the CDI
              -- bytes is a non-empty string, so the pointer cdiBytesPtr will be
              -- non-null
              verifyCDIFFI gcPtr ipInfoPtr nullPtr 0 (castPtr cdiBytesPtr) (fromIntegral cdiBytesLen)
    return (res == 1)
verifyCredential gc ipInfo (Just keys) cdiBytes = unsafeDupablePerformIO $ do
    res <- withGlobalContext gc $ \gcPtr ->
           withIpInfo ipInfo $ \ipInfoPtr ->
           unsafeUseAsCStringLen keyBytes $ \(keyBytesPtr, keyBytesLen) ->
           unsafeUseAsCStringLen cdiBytes $ \(cdiBytesPtr, cdiBytesLen) ->
           -- this use of unsafe is fine since at this point we know the CDI
           -- bytes is a non-empty string, so the pointer cdiBytesPtr will be
           -- non-null
           verifyCDIFFI gcPtr ipInfoPtr (castPtr keyBytesPtr) (fromIntegral keyBytesLen) (castPtr cdiBytesPtr) (fromIntegral cdiBytesLen)
    return (res == 1)
    where keyBytes = encode keys
