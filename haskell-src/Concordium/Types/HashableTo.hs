{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE OverloadedStrings #-}

module Concordium.Types.HashableTo where

import qualified Concordium.Crypto.SHA256 as H
import Concordium.ID.Parameters (GlobalContext)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import Data.Serialize (encode)

class HashableTo hash d where
    getHash :: d -> hash

instance HashableTo H.Hash BS.ByteString where
    getHash = H.hash

instance HashableTo H.Hash LBS.ByteString where
    getHash = H.hashLazy

instance HashableTo H.Hash v => HashableTo H.Hash (Maybe v) where
    getHash Nothing = H.hash "Nothing"
    getHash (Just v) = H.hash ("Just" <> (H.hashToByteString $ getHash v))

instance HashableTo H.Hash GlobalContext where
    getHash val =
        H.hash $
            "CryptoParams"
                <> encode val

-- | While the HashableTo typeclass expects the value
-- to be hashable in a pure environment, sometimes a value
-- might require some monadic context in order to compute
-- its hash, for example if the value might involve reading
-- something from the disk. This class provide an interface
-- for monadic hashing.
--
-- Note that we could have used @HashableTo (m H.Hash) v@ but
-- this way is more semantically explicit. Also, a value that is
-- HashableTo is trivially MHashableTo just by returning its hash.
-- But in order to not produce overlapping instances, we have to
-- declare each instance manually just using the default instance.
class Monad m => MHashableTo m hash v where
    getHashM :: v -> m hash
    default getHashM :: (HashableTo hash v) => v -> m hash
    getHashM = return . getHash

instance Monad m => MHashableTo m H.Hash BS.ByteString

instance Monad m => MHashableTo m H.Hash LBS.ByteString

instance Monad m => MHashableTo m H.Hash GlobalContext

instance (Monad m, HashableTo H.Hash v) => MHashableTo m H.Hash (Maybe v)
