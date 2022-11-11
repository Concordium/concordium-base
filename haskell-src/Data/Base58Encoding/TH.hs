{-# LANGUAGE DerivingVia #-}

module Data.Base58Encoding.TH where

import Data.Maybe
import qualified Data.Vector.Storable as Vec
import Data.Word

import Language.Haskell.TH

codeTable :: Vec.Vector Word8
codeTable = Vec.fromListN 58 (map (fromIntegral . fromEnum) "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

decodeTable :: Vec.Vector Word8
decodeTable = Vec.fromListN 256 (map (\x -> fromIntegral (fromMaybe 255 (Vec.elemIndex x codeTable))) [0 .. 255])

defaultCase :: Match
defaultCase = Match (VarP (mkName "_")) (NormalB (VarE (mkName "undefined"))) []

codeLookup' :: Q Exp
codeLookup' = do
    let name = mkName "x"
    return $
        LamE
            [VarP name]
            ( CaseE (VarE name) $
                [ Match
                    (LitP (IntegerL (fromIntegral i)))
                    (NormalB (LitE (IntegerL (fromIntegral (Vec.unsafeIndex codeTable i)))))
                    []
                  | i <- [0 .. 57]
                ]
                    ++ [defaultCase]
            )

decodeLookup' :: Q Exp
decodeLookup' = do
    let name = mkName "x"
    return $
        LamE
            [VarP name]
            ( CaseE (VarE name) $
                [ Match
                    (LitP (IntegerL (fromIntegral i)))
                    (NormalB (LitE (IntegerL (fromIntegral (Vec.unsafeIndex decodeTable i)))))
                    []
                  | i <- [0 .. 255]
                ]
                    ++ [defaultCase]
            )
