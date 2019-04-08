{-# LANGUAGE MultiParamTypeClasses #-}
module Concordium.GlobalState.HashableTo where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import qualified Concordium.Crypto.SHA256 as H

class HashableTo hash d where
    getHash :: d -> hash

instance HashableTo H.Hash BS.ByteString where
    getHash = H.hash

instance HashableTo H.Hash LBS.ByteString where
    getHash = H.hashLazy