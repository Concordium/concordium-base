module Concordium.Crypto.SecretSharing where

newtype Secret = Secrete ByteString
newtype Share = Share ByteString

share :: Secrete -> Int -> Int -> [Share]
share=undefined

reveal :: [Share] -> Secret
reveal=undefined
