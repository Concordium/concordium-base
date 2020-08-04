{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE OverloadedStrings #-}
module Concordium.Types.HashableTo where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import qualified Concordium.Crypto.SHA256 as H

class HashableTo hash d where
    getHash :: d -> hash

instance HashableTo H.Hash BS.ByteString where
    getHash = H.hash

instance HashableTo H.Hash LBS.ByteString where
    getHash = H.hashLazy

instance HashableTo H.Hash v => HashableTo H.Hash (Maybe v) where
    getHash Nothing = H.hash ""
    getHash (Just v) = getHash v

class Monad m => MHashableTo m hash v where
    getHashM :: v -> m hash
    default getHashM :: (HashableTo hash v) => v -> m hash
    getHashM = return . getHash

instance Monad m => MHashableTo m H.Hash BS.ByteString where

instance Monad m => MHashableTo m H.Hash LBS.ByteString where