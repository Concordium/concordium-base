{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE TemplateHaskell #-}
{-| This module provides a framework for deriving interfaces to the Pointcheval-Sanders
    signature scheme, parametrized by different base curves with pairings.

    The following assumptions are made.

      * There are three groups involved.
      * Group elements have fixed, predetermined size.
      * Field elements have fixed, predetermined size.

    As a consequence the size of values which can be commited is fixed size
    predetermined up front.


-}
module Concordium.Crypto.PointchevalSanders.TH where

import           Concordium.Crypto.ByteStringHelpers
import           Data.Word
import           System.IO.Unsafe
import           Foreign.Ptr
import           Data.Serialize
import qualified Data.FixedByteString as FBS
import           Data.FixedByteString (FixedByteString)
import           Foreign.C.Types
import           Foreign.Storable
import           Foreign.ForeignPtr

import Control.Monad

import Language.Haskell.TH

-- |Parameters used to generate the commitment scheme.
data InternalParameters = InternalParameters {
  deriveCommitmentKeyName :: Name,
  generateSecretKeyName :: Name,
  derivePublicKeyName :: Name,
  signKnownMessageName :: Name,
  signUnknownMessageName :: Name,
  verifySignatureKnownName :: Name,
  retrieveSignatureName :: Name,
  commitWithPublicKeyName :: Name,
  randomValuesName :: Name,
  parameters :: Parameters
  } deriving(Show)

mkForeignImports :: InternalParameters -> Q [Dec]
mkForeignImports InternalParameters{parameters=Parameters{..},..} = do
  -- Generate the secret key.
  -- The argument is the number of values we will want to work with, the output array must be of size.
  -- (n+1) * fieldElementSize.
  -- This function is __NOT__ pure.
  genSecretKey <- forImpD cCall unsafe cGenerateSecretKey generateSecretKeyName [t|CSize -> Ptr Word8 -> IO ()|]
  -- Compute the public key from the secret key.
  -- The first argument is the number of values (must be the same as when used to generate secret key),
  -- the second argument is the secret key, and the third input argument is the array where the public key is written.
  -- The return value is -1 if secret key was malformed and 1 in case of successful generation of public key.
  -- This function is pure.
  derivePublic <- forImpD cCall unsafe cDerivePublicKey derivePublicKeyName [t| CSize -> Ptr Word8 -> Ptr Word8 -> CInt|]
  -- sign a known message.
  -- input n, secret key, message, last argument is output array where the signature is written.
  -- the returned value is
  -- -1 if secret key malformed
  -- -2 if message malformed (not valid field elements)
  -- -3 if there is an error generating the signature
  -- 1 if signing succeeds.
  -- This function is not pure (generates randomness)
  signKnown <- forImpD cCall unsafe cSignKnownMessage signKnownMessageName [t| CSize -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt|]
  -- sign an unknown message.
  -- secret key, encrypted message, last argument is output array where the signature is written.
  -- the returned value is
  -- -1 if secret key malformed
  -- -2 if message malformed (not valid field elements)
  -- -3 if there is an error generating the signature
  -- 1 if signing succeeds.
  -- This function is not pure (generates randomness)
  signUnknown <- forImpD cCall unsafe cSignUnknownMessage signUnknownMessageName [t| Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt|]
  -- verify a signature of known message
  -- inputs n, public key, signature, message
  -- output 
  -- -1 if public key malformed
  -- -2 if signature malformed
  -- -3 if message malformed
  -- 0 if signature does not validate
  -- 1 if signature validates
  -- This function is pure.
  verifySignature <- forImpD cCall unsafe cVerifySignatureKnown verifySignatureKnownName [t| CSize -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> CInt|]
  -- generate a commitment key from the public key
  -- input n, public key, array to write commitment key
  -- output -1 if public key malformed, and 1 if successful
  deriveCommitment <- forImpD cCall unsafe cDeriveCommitmentKey deriveCommitmentKeyName [t| CSize -> Ptr Word8 -> Ptr Word8 -> CInt|]
  -- retrieve signature of the original message from the signature of the commitment
  -- input secret key, commitment key, randomness bytes, array to write signature of original message
  -- return is
  -- -1 if original signature malformed
  -- -3 if randomness malformed
  -- 1 if everything OK
  -- This function is pure.
  retrieveSig <- forImpD cCall unsafe cRetrieveSignature retrieveSignatureName [t| Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> CInt |]
  -- Commit to a list of values.
  -- public key, message,  to write the commitment, and array to write the randomness.
  -- return value is
  -- -1 if public key malformed
  -- -2 if message malformed
  -- 1 if everything OK
  commitWithPK <- forImpD cCall unsafe cCommitWithPublicKey commitWithPublicKeyName [t| CSize -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt|]

  randomValuesImport <- forImpD cCall unsafe cRandomValuesName randomValuesName [t| CSize -> Ptr Word8 -> IO ()|]
  return [genSecretKey,
          derivePublic,
          signKnown,
          signUnknown,
          verifySignature,
          deriveCommitment,
          retrieveSig,
          commitWithPK,
          randomValuesImport]

mkDataTysAndTerms :: InternalParameters -> Q [Dec]
mkDataTysAndTerms InternalParameters{parameters=Parameters{..},..} =
  [d|
     publicKeySize :: Int -> Int
     publicKeySize n = n * groupG1ElementSize + (n+1) * groupG2ElementSize

     messageSize :: Int -> Int
     messageSize n = n * fieldElementSize

     randomnessSize :: Int
     randomnessSize = fieldElementSize

     unknownMessageSize :: Int
     unknownMessageSize = groupG1ElementSize

     signatureSize :: Int
     signatureSize = 2 * groupG1ElementSize

     secretKeySize :: Int -> Int
     secretKeySize n = (n+1) * fieldElementSize

     commitmentKeySize :: Int -> Int
     commitmentKeySize n = (n+1) * groupG1ElementSize
     
     data ValueSize
     instance FBS.FixedLength ValueSize where
         fixedLength _ = fieldElementSize

     data RandomnessSize
     instance FBS.FixedLength RandomnessSize where
         fixedLength _ =  randomnessSize
     
     data UnknownMessageSize
     instance FBS.FixedLength UnknownMessageSize where
         fixedLength _ = unknownMessageSize

     data SignatureSize
     instance FBS.FixedLength SignatureSize where
         fixedLength _ = signatureSize

     -- Value encoded as a field element.
     newtype EncodedValue = EncodedValue (FixedByteString ValueSize)
         deriving(Eq, Storable)

     instance Show EncodedValue where
       show (EncodedValue v) = fbsHex v

     instance Serialize EncodedValue where
         put (EncodedValue v) = fbsPut v
         get = EncodedValue <$> fbsGet

     type EncodedValues = [EncodedValue]

     newtype Randomness = Randomness (FixedByteString RandomnessSize)
         deriving (Eq)

     instance Show Randomness where
       show (Randomness r) = byteStringToHex (FBS.toByteString r)

     instance Serialize Randomness where
         put (Randomness c) = fbsPut c
         get = Randomness <$> fbsGet

     newtype Commitment = Commitment (FixedByteString UnknownMessageSize)
         deriving (Eq)
     instance Serialize Commitment where
         put (Commitment c) = fbsPut c
         get = Commitment <$> fbsGet
     instance Show Commitment where
         show (Commitment c) = fbsHex c

     data SecretKey = SecretKey !Int !(ForeignPtr Word8)
     instance Eq SecretKey where
       SecretKey l1 p1 == SecretKey l2 p2 = l1 == l2 && unsafeEqForeignPtr l1 p1 p2
     instance Show SecretKey where
       show (SecretKey l p) = unsafeForeignPtrHex l p
     instance Serialize SecretKey where
       put (SecretKey n fp) = putForeignPtrWord8 n fp
       get = uncurry SecretKey <$> getForeignPtrWord8

     data PublicKey = PublicKey !Int !(ForeignPtr Word8)
     instance Eq PublicKey where
       PublicKey l1 p1 == PublicKey l2 p2 = l1 == l2 && unsafeEqForeignPtr l1 p1 p2
     instance Show PublicKey where
       show (PublicKey l p) = unsafeForeignPtrHex l p
     instance Serialize PublicKey where
       put (PublicKey n fp) = putForeignPtrWord8 n fp
       get = uncurry PublicKey <$> getForeignPtrWord8


     data CommitmentKey = CommitmentKey !Int !(ForeignPtr Word8)
     instance Eq CommitmentKey where
       CommitmentKey l1 p1 == CommitmentKey l2 p2 = l1 == l2 && unsafeEqForeignPtr l1 p1 p2
     instance Show CommitmentKey where
       show (CommitmentKey l p) = unsafeForeignPtrHex l p
     instance Serialize CommitmentKey where
       put (CommitmentKey n fp) = putForeignPtrWord8 n fp
       get = uncurry CommitmentKey <$> getForeignPtrWord8

     newtype Signature = Signature (FixedByteString SignatureSize)
       deriving(Eq)
     instance Show Signature where
       show (Signature s) = fbsHex s
     instance Serialize Signature where
       put (Signature fbs) = fbsPut fbs
       get = Signature <$> fbsGet

     withSecretKey :: SecretKey -> (Ptr Word8 -> IO a) -> IO a
     withSecretKey (SecretKey _ sk_bytes) = withForeignPtr sk_bytes 

     withSecretKeyLast :: SecretKey -> (Ptr Word8 -> IO a) -> IO a
     withSecretKeyLast (SecretKey n sk_bytes) f = 
       withForeignPtr sk_bytes $
         \wordPtr -> f (wordPtr `plusPtr` (n - fieldElementSize))


     withPublicKey :: PublicKey -> (Ptr Word8 -> IO a) -> IO a
     withPublicKey (PublicKey _ pk_bytes) = withForeignPtr pk_bytes 

     withCommitment :: Commitment -> (Ptr Word8 -> IO a) -> IO a
     withCommitment (Commitment fbs) = FBS.withPtr fbs

     withRandomness :: Randomness -> (Ptr Word8 -> IO a) -> IO a
     withRandomness (Randomness fbs) = FBS.withPtr fbs

     withCommitmentKey :: CommitmentKey -> (Ptr Word8 -> IO a) -> IO a
     withCommitmentKey (CommitmentKey _ ck) = withForeignPtr ck

     withSignature :: Signature -> (Ptr Word8 -> IO a) -> IO a
     withSignature (Signature fbs) = FBS.withPtr fbs

     -- Generates a new secret key for the given number of values to commit and sign.
     newSecretKey :: Int -> IO SecretKey
     newSecretKey n = 
         do bytes <- mallocForeignPtrBytes (secretKeySize n)
            withForeignPtr bytes $ \sk -> $(varE generateSecretKeyName) (fromIntegral n) sk
            return $! SecretKey (secretKeySize n) bytes

     -- Derive public key from secret key. If secret key is malformed return 'Nothing'.
     derivePublicKey :: Int -> SecretKey -> Maybe PublicKey
     derivePublicKey n sk = unsafeDupablePerformIO $ do
       pk_bytes <- mallocForeignPtrBytes (publicKeySize n)
       suc <- withSecretKey sk $
                \sk_bytes -> withForeignPtr pk_bytes $ \pk_bytes' -> 
                  return $! $(varE derivePublicKeyName) (fromIntegral n) sk_bytes pk_bytes'
       if suc == 1 then
         return $! Just (PublicKey (publicKeySize n) pk_bytes)
       else return Nothing

     data SignResult = SignSecretKeyMalformed
                       | SignMessageMalformed
                       | SignCannotSign
                       | SignSuccess !Signature
       deriving(Eq, Show)

     withEncodedValues :: Int -> EncodedValues -> (Ptr Word8 -> IO a) -> IO a
     withEncodedValues n vals f = do
       bytes <- mallocForeignPtrBytes (n * fieldElementSize)
       withForeignPtr bytes $
         \wordPtr ->
           let valPtr = castPtr wordPtr
           in do zipWithM_ (pokeElemOff valPtr) [0..n-1] vals
                 f wordPtr

     signKnownMessage :: Int -> SecretKey -> EncodedValues -> IO SignResult
     signKnownMessage n sk vals = do
       sig_bytes <- mallocForeignPtrBytes signatureSize
       suc <- withSecretKey sk $
                \sk_bytes -> withEncodedValues n vals $
                  \msg_bytes -> withForeignPtr sig_bytes $
                    \sig_bytes' -> $(varE signKnownMessageName) (fromIntegral n) sk_bytes msg_bytes sig_bytes'
       return $!
         case suc of
           k | k == -1 -> SignSecretKeyMalformed
             | k == -2 -> SignMessageMalformed
             | k == -3 -> SignCannotSign
             | otherwise -> SignSuccess (Signature (FBS.FixedByteString sig_bytes))

     signUnknownMessage :: SecretKey -> Commitment -> IO SignResult
     signUnknownMessage sk umsg = do
       sig_bytes <- mallocForeignPtrBytes signatureSize
       suc <- withSecretKeyLast sk $
                \sk_bytes -> withCommitment umsg $
                  \msg_bytes -> withForeignPtr sig_bytes $ $(varE signUnknownMessageName) sk_bytes msg_bytes
       return $!
         case suc of
           k | k == -1 -> SignSecretKeyMalformed
             | k == -2 -> SignMessageMalformed
             | k == -3 -> SignCannotSign
             | otherwise -> SignSuccess (Signature (FBS.FixedByteString sig_bytes))

     data VerifyResult = VerifyPublicKeyMalformed
                       | VerifySignatureMalformed
                       | VerifyMessageMalformed
                       | VerifySignatureIncorrect
                       | VerifySignatureOK
       deriving(Eq, Show)

     verifySignature :: Int -> PublicKey -> Signature -> EncodedValues -> VerifyResult
     verifySignature n pk sig vals = unsafeDupablePerformIO $ do
       suc <- withPublicKey pk $
                \pk_bytes -> withSignature sig $
                  \sig_bytes -> withEncodedValues n vals $
                    \msg_bytes -> return $! $(varE verifySignatureKnownName) (fromIntegral n) pk_bytes sig_bytes msg_bytes
       return $!
         case suc of
           k | k == -1 -> VerifyPublicKeyMalformed
             | k == -2 -> VerifySignatureMalformed
             | k == -3 -> VerifyMessageMalformed
             | k == 0 -> VerifySignatureIncorrect
             | otherwise -> VerifySignatureOK
                
     deriveCommitmentKey :: Int -> PublicKey -> Maybe CommitmentKey
     deriveCommitmentKey n pk = unsafeDupablePerformIO $ do
       ck_bytes <- mallocForeignPtrBytes (commitmentKeySize n)
       suc <- withPublicKey pk $
                \pk_bytes -> withForeignPtr ck_bytes $
                  \ck_bytes' -> return $! $(varE deriveCommitmentKeyName) (fromIntegral n) pk_bytes ck_bytes'
       if suc == 1 then
         return $! Just (CommitmentKey (commitmentKeySize n) ck_bytes)
       else return Nothing

     data RetrieveResult = RetrieveOrigSignatureMalformed
                         | RetrieveRandomnessMalformed
                         | RetrieveSignatureOK !Signature
       deriving(Eq, Show)

     retrieveSignature :: Signature -> Randomness -> RetrieveResult
     retrieveSignature sig r = unsafeDupablePerformIO $ do
       retrieved_sig_bytes <- mallocForeignPtrBytes signatureSize
       suc <- withSignature sig $
                \orig_sig_bytes -> withRandomness r $
                    \randomness_bytes -> withForeignPtr retrieved_sig_bytes $
                      \retrieved_sig_bytes' -> return $! $(varE retrieveSignatureName)
                                                         orig_sig_bytes
                                                         randomness_bytes
                                                         retrieved_sig_bytes'
       return $!
         case suc of
           k | k == -1 -> RetrieveOrigSignatureMalformed
             | k == -2 -> RetrieveRandomnessMalformed
             | otherwise -> RetrieveSignatureOK (Signature (FBS.FixedByteString retrieved_sig_bytes))

     data CommitResult = CommitPublicKeyMalformed
                       | CommitValuesMalformed
                       | CommitSuccess !Commitment !Randomness

     commitWithPublicKey :: Int -> PublicKey -> EncodedValues -> IO CommitResult
     commitWithPublicKey n pk vals = do
       unknown_msg_bytes <- mallocForeignPtrBytes unknownMessageSize
       randomness_bytes <- mallocForeignPtrBytes randomnessSize
       suc <- withPublicKey pk $
                \pk_bytes -> withEncodedValues n vals $
                  \value_bytes -> withForeignPtr unknown_msg_bytes $
                    \unknown_msg_bytes' -> withForeignPtr randomness_bytes $
                      $(varE commitWithPublicKeyName) (fromIntegral n) pk_bytes value_bytes unknown_msg_bytes'
       return $!
         case suc of
           k | k == -1 -> CommitPublicKeyMalformed
             | k == -2 -> CommitValuesMalformed
             | otherwise -> CommitSuccess (Commitment (FBS.FixedByteString unknown_msg_bytes)) (Randomness (FBS.FixedByteString randomness_bytes))

     -- Produce the given number of valid values.
     -- note that the order of values is the reverse of that generated by rust
     -- it shouldn't matter
     randomValues:: Int -> IO EncodedValues
     randomValues n = mapM (\_ -> EncodedValue <$> FBS.create ($(varE randomValuesName) 1)) [1..n]

  |]

-- |Parameters used to generate the commitment scheme.
data Parameters = Parameters  {
  -- |Name of the c function to derive the commitment key from the public key.
  cDeriveCommitmentKey :: String,
  -- |Name of the c function to generate the secret key.
  cGenerateSecretKey :: String,
  -- |Name of the c function to derive public key from secret key.
  cDerivePublicKey :: String,
  -- |Name of the c function to sign a __known__ message.
  cSignKnownMessage :: String,
  -- |Name of the c function to sign an __unknown__ message.
  cSignUnknownMessage :: String,
  -- |Name of the c function to verify a signature given the known message.
  cVerifySignatureKnown :: String,
  -- |Name of the c function to compute signature of the original message given
  -- the signtaure of the commitment.
  cRetrieveSignature :: String,
  -- |Name of the c function to commit to a list of values given a public key.
  cCommitWithPublicKey :: String,

  -- |A c function to generate random values, e.g., to use for testing.
  cRandomValuesName :: String,

  -- Size parameters.
  -- This signature scheme is parametrized over an underlying curve with pairing.
  -- This pairing is a mapping of type G1 x G2 -> G~
  -- The sizes of group elements in G1 and G2, as well as the size of field
  -- elements (scalars) are parameters of the scheme .

  -- |Size of elements (in bytes) in the first group.
  groupG1ElementSize :: Int,
  -- |Size of elements (in bytes) in the second group.
  groupG2ElementSize :: Int,
  -- |Size of field elements in bytes.
  fieldElementSize :: Int
  } deriving(Show)

-- |TODO: Documentation ...
mkPointChevalScheme :: Parameters -> Q [Dec]
mkPointChevalScheme parameters@Parameters{..} = 
    let deriveCommitmentKeyName = mkName cDeriveCommitmentKey
        generateSecretKeyName = mkName cGenerateSecretKey
        derivePublicKeyName = mkName cDerivePublicKey
        signKnownMessageName = mkName cSignKnownMessage
        signUnknownMessageName = mkName cSignUnknownMessage
        verifySignatureKnownName = mkName cVerifySignatureKnown
        retrieveSignatureName = mkName cRetrieveSignature
        commitWithPublicKeyName = mkName cCommitWithPublicKey
        randomValuesName = mkName cRandomValuesName
        iparams = InternalParameters{..}
  in do
    foreignImports <- mkForeignImports iparams
    tysandterms <- mkDataTysAndTerms iparams
    return $ foreignImports ++ tysandterms
