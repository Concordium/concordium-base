{-# LANGUAGE OverloadedStrings #-}

module Concordium.ID.Account (CredentialDeploymentInformationBytes, verifyCredential, verifyInitialAccountCreation) where

import Data.ByteString.Unsafe
import Data.Int
import Foreign.C.Types
import Foreign.Marshal.Array
import Foreign.Ptr
import GHC.Word
import System.IO.Unsafe

import Data.ByteString as BS

import Concordium.ID.AnonymityRevoker
import Concordium.ID.IdentityProvider
import Concordium.ID.Parameters
import Concordium.ID.Types
import Concordium.Types
import qualified Data.FixedByteString as FBS

type CredentialDeploymentInformationBytes = ByteString

foreign import ccall safe "verify_cdi_ffi"
    verifyCDIFFI ::
        Ptr GlobalContext ->
        Ptr IpInfo ->
        Ptr (Ptr ArInfo) ->
        -- |Length of the ArInfo list.
        CSize ->
        -- |Serialized credential.
        Ptr Word8 ->
        -- |Length of the serialized credential.
        CSize ->
        -- | Pointer to the account address, or null if credential creates the account.
        Ptr Word8 ->
        -- | If the previous argument is Null then this is used, it is the expiry date of a credential.
        TransactionTime ->
        IO Int32

-- FIXME: We pass in keys as byte arrays which is quite bad since
-- keys are not bytes, but rather we know that they are well-formed already.

foreign import ccall safe "verify_initial_cdi_ffi"
    verifyInitialCDIFFI ::
        Ptr IpInfo ->
        -- | Serialized account creation information
        Ptr Word8 ->
        -- | Length of serialized account creation information
        CSize ->
        -- | Expiry of the initial credential message.
        TransactionTime ->
        IO Int32

withArInfoArray :: [Ptr ArInfo] -> [ArInfo] -> (Int -> Ptr (Ptr ArInfo) -> IO a) -> IO a
withArInfoArray arPtrs [] k = withArrayLen arPtrs k
withArInfoArray arPtrs (ar : ars) k = withArInfo ar $ \arPtr -> withArInfoArray (arPtr : arPtrs) ars k

withAccountAddress :: AccountAddress -> (Ptr Word8 -> IO a) -> IO a
withAccountAddress (AccountAddress fbs) = FBS.withPtrReadOnly fbs

-- |Verify a credential in the context of the given cryptographic parameters and
-- identity provider information. If the account keys are given this checks that
-- the proofs contained in the credential correspond to them.
verifyCredential :: GlobalContext -> IpInfo -> [ArInfo] -> CredentialDeploymentInformationBytes -> Either TransactionTime AccountAddress -> Bool
verifyCredential gc ipInfo arInfos cdiBytes (Left tt) = unsafePerformIO $ do
    res <- withGlobalContext gc $ \gcPtr ->
        withIpInfo ipInfo $ \ipInfoPtr ->
            withArInfoArray [] arInfos $ \len arPtr ->
                unsafeUseAsCStringLen cdiBytes $ \(cdiBytesPtr, cdiBytesLen) -> do
                    -- this use of unsafe is fine since at this point we know the CDI
                    -- bytes is a non-empty string, so the pointer cdiBytesPtr will be
                    -- non-null
                    verifyCDIFFI gcPtr ipInfoPtr arPtr (fromIntegral len) (castPtr cdiBytesPtr) (fromIntegral cdiBytesLen) nullPtr tt
    return (res == 1)
verifyCredential gc ipInfo arInfos cdiBytes (Right address) = unsafePerformIO $ do
    res <- withAccountAddress address $ \accountAddressPtr ->
        withGlobalContext gc $ \gcPtr ->
            withIpInfo ipInfo $ \ipInfoPtr ->
                withArInfoArray [] arInfos $ \len arPtr ->
                    unsafeUseAsCStringLen cdiBytes $ \(cdiBytesPtr, cdiBytesLen) ->
                        -- this use of unsafe is fine since at this point we know the CDI
                        -- bytes is a non-empty string, so the pointer cdiBytesPtr will be
                        -- non-null
                        verifyCDIFFI
                            gcPtr
                            ipInfoPtr
                            arPtr
                            (fromIntegral len)
                            (castPtr cdiBytesPtr)
                            (fromIntegral cdiBytesLen)
                            accountAddressPtr
                            0 -- this argument is not used because the account address is not null.
    return (res == 1)

type InitialCredentialBytes = ByteString

-- |Verify the initial account creation payload, in the context of the given
-- identity provider.
verifyInitialAccountCreation :: IpInfo -> TransactionTime -> InitialCredentialBytes -> Bool
verifyInitialAccountCreation ipInfo tt aciBytes = unsafePerformIO $ do
    res <- withIpInfo ipInfo $ \ipInfoPtr ->
        unsafeUseAsCStringLen aciBytes $ \(aciBytesPtr, aciBytesLen) ->
            -- This use of unsafe is fine, since 'verifyInitialCDIFFI' respects the length, and will
            -- not dereference the pointer if the length is 0.
            verifyInitialCDIFFI ipInfoPtr (castPtr aciBytesPtr) (fromIntegral aciBytesLen) tt
    return (res == 1)
