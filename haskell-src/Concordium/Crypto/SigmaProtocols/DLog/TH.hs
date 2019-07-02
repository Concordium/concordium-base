{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE FlexibleInstances #-}
module Concordium.Crypto.SigmaProtocols.DLog.TH
  (DLogProof,
   Public,
   Secret,
   Base,
   Parameters(..),
   mkDLog
  )
  where

import Data.ByteString
import Concordium.Crypto.ByteStringHelpers
import Concordium.Crypto.FFIHelpers
import Foreign.Ptr
import Foreign.ForeignPtr
import Data.Word
import Data.Int
import System.IO.Unsafe
import Foreign.C.Types
import Language.Haskell.TH

import Data.Proxy

import Concordium.Crypto.Curve

-- |The parameter is a phantom one and should match the Curve parameter.
-- The tag is used to link this proof to the underlying curve.
newtype DLogProof a = DLogProof (ForeignPtr (DLogProof a))

type Secret a = FieldElement a
type Public a = GroupElement a
type Base a = GroupElement a

withProof :: DLogProof a -> (Ptr (DLogProof a) -> IO b) -> IO b
withProof (DLogProof fp) = withForeignPtr fp

data InternalParameters = InternalParameters {
  proveName :: Name,
  verifyName :: Name,
  toBytesName :: Name,
  fromBytesName :: Name,
  freeProofName :: Name,
  derivePublicName :: Name,
  parameters :: Parameters
  }

mkForeignImports :: InternalParameters -> Q [Dec]
mkForeignImports InternalParameters{parameters=Parameters{..},..} =
   mapM (\(cname, name, ty) -> forImpD cCall unsafe cname name ty) $ [
     ('&':cFreeProofName, freeProofName, [t| FunPtr (Ptr (DLogProof $(conT tagName)) -> IO ())|]),
     (cProveName, proveName, [t| Ptr (Public $(conT tagName))
                                 -> Ptr (Secret $(conT tagName))
                                 -> Ptr (Base $(conT tagName))
                                 -> IO (Ptr (DLogProof $(conT tagName)))|]),
     (cVerifyName, verifyName, [t| Ptr (Base $(conT tagName))
                                -> Ptr (Public $(conT tagName))
                                -> Ptr (DLogProof $(conT tagName))
                                -> Int32 |]),
     (cDerivePublicName, derivePublicName, [t| Ptr (Base $(conT tagName))
                                                -> Ptr (Secret $(conT tagName))
                                                -> IO (Ptr (Public $(conT tagName))) |]),
     (cFromBytesName, fromBytesName, [t| Ptr Word8 -> CSize -> IO (Ptr (DLogProof $(conT tagName))) |]),
     (cToBytesName, toBytesName, [t| Ptr (DLogProof $(conT tagName)) -> Ptr CSize -> IO (Ptr Word8) |])
  ]

mkFuncs :: InternalParameters -> Q [Dec]
mkFuncs InternalParameters{parameters=Parameters{..},..} = [d|
  -- not declaring a serialize instance in order to avoid orphan instances
  getProof :: ByteString -> Maybe (DLogProof $(conT tagName))
  getProof bs = DLogProof <$> fromBytesHelper $(varE freeProofName) $(varE fromBytesName) bs

  putProof :: DLogProof $(conT tagName) -> ByteString
  putProof (DLogProof e) = toBytesHelper $(varE toBytesName) $ e

  showProof :: DLogProof $(conT tagName) -> String
  showProof = byteStringToHex . putProof

  prove :: Public $(conT tagName) -> Secret $(conT tagName) -> Base $(conT tagName) -> IO (DLogProof $(conT tagName))
  prove public secret base =
    withGroupElement public $ \public_ptr ->
      withFieldElement (Proxy :: Proxy $(conT tagName)) secret $ \secret_ptr ->
        withGroupElement base $ \base_ptr ->
          DLogProof <$> (newForeignPtr $(varE freeProofName) =<< $(varE proveName) public_ptr secret_ptr base_ptr)

  verify :: Base $(conT tagName) -> Public $(conT tagName) -> DLogProof $(conT tagName) -> Bool
  verify base public proof = unsafeDupablePerformIO $
    withGroupElement base $ \base_ptr ->
      withGroupElement public $ \public_ptr ->
        withProof proof $ \proof_ptr ->
          return (1 == $(varE verifyName) base_ptr public_ptr proof_ptr)

  derivePublic :: Base $(conT tagName) -> Secret $(conT tagName) -> Public $(conT tagName)
  derivePublic base secret = unsafeDupablePerformIO $
    withGroupElement base $ \base_ptr ->
      withFieldElement (Proxy :: Proxy $(conT tagName)) secret $ \secret_ptr ->
        groupElementFromPtr =<< $(varE derivePublicName) base_ptr secret_ptr

 |]

data Parameters = Parameters {
  cProveName :: String,
  cVerifyName :: String,
  cToBytesName :: String,
  cFromBytesName :: String,
  cFreeProofName :: String,
  cDerivePublicName :: String,
  tagName :: Name
  }

mkDLog :: Parameters -> Q [Dec]
mkDLog parameters@Parameters{..} =
  let proveName = mkName cProveName
      verifyName = mkName cVerifyName
      toBytesName = mkName cToBytesName
      fromBytesName = mkName cFromBytesName
      freeProofName = mkName cFreeProofName
      derivePublicName = mkName cDerivePublicName
      iparams = InternalParameters{..}
  in do fimps <- mkForeignImports iparams
        decls <- mkFuncs iparams
        return $ fimps ++ decls
