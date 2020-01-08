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
