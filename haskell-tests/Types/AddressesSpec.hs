module Types.AddressesSpec where

import Test.Hspec
import Test.QuickCheck as QC
import Data.Hashable

import Concordium.Types
import Concordium.ID.Types
import qualified Data.FixedByteString as FBS

genAddress :: Gen AccountAddress
genAddress = do
  AccountAddress . FBS.pack <$> vector accountAddressSize

genAliases :: AccountAddress -> Gen AccountAddress
genAliases (AccountAddress addr) = do
  suffix <- vector 3
  return $ AccountAddress . FBS.pack $ (take accountAddressPrefixSize (FBS.unpack addr) ++ suffix)

-- Test that AccountAddressEq has the correct hashable and eq instances that do
-- not distinguish aliases.
testEquivalence :: Property
testEquivalence = forAll genAddress $ \addr ->
  forAll (genAliases addr) $ \alias ->
    forAll arbitrary $ \salt -> 
      accountAddressEmbed addr === accountAddressEmbed alias .&&.
      hash (accountAddressEmbed addr) === hash (accountAddressEmbed alias) .&&.
      hashWithSalt salt (accountAddressEmbed addr) === hashWithSalt salt (accountAddressEmbed alias)


-- Given an address generate corrupt addresses that differ from it on a single
-- byte. This is done so there is non-trivial chance of equivalent addresses
-- compared to just generating fresh addresses.
genCorrupt :: AccountAddress -> Gen AccountAddress
genCorrupt (AccountAddress addr) = do
  place <- choose (0, 31)
  let (start, ~(_:rest)) = splitAt place (FBS.unpack addr) -- since we split at most at 31 there is at least one element of the tail
  new <- arbitrary
  return $ AccountAddress . FBS.pack $ (start ++ new:rest)

-- Dual to the test above, check that equivalence does not identify more than 29 bytes.
testNegative :: Property
testNegative = forAll genAddress $ \addr@(AccountAddress addrFbs) ->
  forAll (genCorrupt addr) $ \maybeAlias@(AccountAddress maybeAliasFbs) ->
      accountAddressEmbed addr =/= accountAddressEmbed maybeAlias .||. 
      take accountAddressPrefixSize (FBS.unpack addrFbs) === take accountAddressPrefixSize (FBS.unpack maybeAliasFbs)

tests :: Spec
tests = do
  specify "Account address equivalence" $ withMaxSuccess 100000 $ testEquivalence
  specify "Account address equivalence does not identify too much" $ withMaxSuccess 100000 $ testNegative
