module Concordium.ID.AccountHolder where

import Concordium.ID.Types
import Data.ByteString.Char8
import Data.ByteString.Random.MWC
import System.IO.Unsafe





-- This is a dummy module for testing
--

createAccount :: AccountHolderCertificate -> AccountCreationInformation  
createAccount ahc = undefined

verifyAccount :: AccountCreationInformation -> Bool 
verifyAccount = true


ar :: AnonimityRevoker
ar = AR (AR_ID $ pack "superman") (AR_PK $ unsafePerformIO $ random (fromIntegral 32))


