{-# LANGUAGE TypeFamilies #-}
module Concordium.ID.Types where

import qualified Data.ByteString    as BS
import           Data.ByteString    (ByteString)
import           Data.Dates
import           Concordium.ID.Attributes
import           Concoridum.Crypto.Signature

data AccountHolderCertificate 

-- Secret Key of Account Holder
newtype SecretIdenityCredentials = IdCredSec ByteString

-- Public Key of Account Holder
newtype PublicIdenityCredentials = IdCredPub ByteString

-- A secret key to generate Account Registration ID
newtype PseudoRandomFunctionKey   = PRFKey ByteString

-- Public key of Anonimity Revoker (Elgamal)
newtype AnonimityRevokerPublicKey = AR_PK ByteString

-- Private key of Anonimity Revoker (Elgamal)
newtype AnonimityRevokerPrivateKey = AR_SK ByteString

-- Name of Identity Revoker
newtype AnonimityRevokerIdentity  = AR_ID String

data AnonimityRevoker = AR AnonimityRevokerIdentity AnonimityRevokerPublicKey
                         

-- Signing key for accounts (eddsa key)
newtype AccountSignatureKey = SigKeyAcc ByteString

-- Verification key for accounts (eddsa key)
newtype AccountVerificationKey = SerifKeyAcc ByteString


-- decryption key for accounts (Elgamal?)
newtype AccountDecryptionKey = DecKeyAcc ByteString 

-- encryption key for accounts (Elgamal?)
newtype AccountencryptionKey = EncKeyAcc ByteString 

-- Account Registration ID
newtype AccountRegistrationID = RegIdAcc ByteString

newtype SecretShare = Share ByteString

--AR Data
newtype AccountAnonimityRevocationData = [(AnonimityRevoker, SecretShare)] 


-- ZK proofs

data Statement = Statement (ByteString -> Bool)

data Witness = Witness ByteString 

data ZKProof = Proof ByteString

