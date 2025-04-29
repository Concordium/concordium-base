{-# LANGUAGE DerivingVia #-}

-- | This module defines the 'Memo' type and associated functionality.
module Concordium.Types.Memo where

import Control.Monad
import Control.Monad.Except

import qualified Concordium.Crypto.ByteStringHelpers as BSH
import qualified Data.Aeson as AE
import qualified Data.ByteString.Short as BSS
import qualified Data.Serialize as S

-- | Helper function to render an error when a bytestring value is too large.
tooBigErrorString ::
    -- | Name
    String ->
    -- | Actual size
    Int ->
    -- | Maximum size
    Int ->
    String
tooBigErrorString name len maxSize =
    "Size of the "
        ++ name
        ++ " ("
        ++ show len
        ++ " bytes) exceeds maximum allowed size ("
        ++ show maxSize
        ++ " bytes)."

-- | Data type for memos that can be added to transfers.
--  Max length of 'maxMemoSize' is assumed.
--  Create new values with 'memoFromBSS' to ensure assumed properties.
--
--  Note that the ToJSON instance of this type is derived, based on hex encoding.
--  The FromJSON instance is manually implemented to ensure length limits.
newtype Memo = Memo BSS.ShortByteString
    deriving (Eq)
    deriving (AE.ToJSON, Show) via BSH.ByteStringHex

-- | Maximum size for 'Memo'.
maxMemoSize :: Int
maxMemoSize = 256

-- | Construct 'Memo' from a 'BSS.ShortByteString'.
--  Fails if the length exceeds 'maxMemoSize'.
memoFromBSS :: (MonadError String m) => BSS.ShortByteString -> m Memo
memoFromBSS bss =
    if len <= maxMemoSize
        then return . Memo $ bss
        else throwError $ tooBigErrorString "memo" len maxMemoSize
  where
    len = BSS.length bss

instance S.Serialize Memo where
    put (Memo bss) = do
        S.putWord16be . fromIntegral . BSS.length $ bss
        S.putShortByteString bss

    get = S.label "Memo" $ do
        l <- fromIntegral <$> S.getWord16be
        unless (l <= maxMemoSize) $ fail $ tooBigErrorString "memo" l maxMemoSize
        Memo <$> S.getShortByteString l

instance AE.FromJSON Memo where
    parseJSON v = do
        (BSH.ByteStringHex bss) <- AE.parseJSON v
        case memoFromBSS bss of
            Left err -> fail err
            Right rd -> return rd
