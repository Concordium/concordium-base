module Types.UpdatesSpec where

import Control.Monad
import qualified Data.Aeson as AE
import Test.Hspec
import Test.QuickCheck as QC

import Concordium.Types.Updates
{-
genUpdatePayload :: Gen UpdatePayload
genUpdatePayload = oneof [
        AuthorizationUpdatePayload <$> genAuthorizations,
        ProtocolUpdatePayload <$> genProtocolUpdate,
        ElectionDifficultyUpdatePayload <$> ]

genUpdateInstruction :: Gen UpdateInstruction
genUpdateInstruction = do
        uiPayload <- genUpdatePayload
        return UpdateInstruction{..}
        -}