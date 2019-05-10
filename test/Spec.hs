module Main where

import qualified Types.PayloadSerializationSpec(tests)
import qualified Types.SerializationSpec(testExpr, testModule)
import qualified Types.ArithmeticSpec(tests)

import Test.Hspec
import Test.Hspec.QuickCheck

main :: IO ()
main = hspec $ parallel $ do
         describe "Acorn serialization tests" $ do
           modifyMaxSuccess (const 1000) $ Types.SerializationSpec.testExpr 25
           modifyMaxSuccess (const 500) $ Types.SerializationSpec.testExpr 50
           modifyMaxSuccess (const 250) $ Types.SerializationSpec.testExpr 75
           modifyMaxSuccess (const 100) $ Types.SerializationSpec.testExpr 100
         
           modifyMaxSuccess (const 1000) $ Types.SerializationSpec.testModule 10
           modifyMaxSuccess (const 500) $ Types.SerializationSpec.testModule 25

         Types.PayloadSerializationSpec.tests

         Types.ArithmeticSpec.tests
