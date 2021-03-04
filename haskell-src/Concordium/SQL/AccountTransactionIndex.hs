{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE StandaloneDeriving #-}
module Concordium.SQL.AccountTransactionIndex where

import Concordium.Common.Time
import Concordium.Types(BlockHash, AccountAddress)
import Concordium.Types.SmartContracts
import Concordium.Types.Block

import Database.Persist.Postgresql
import Database.Persist.Postgresql.JSON()
import Database.Persist.TH
import qualified Data.Aeson as AE

import Concordium.SQL.Helpers

share [mkPersist sqlSettings, mkMigrate "migrateAll"] [persistLowerCase|
  Summary sql=summaries
    block (ByteStringSerialized BlockHash)
    timestamp Timestamp
    height BlockHeight
    summary AE.Value
    deriving Eq Show

  Entry sql=ati
    account (ByteStringSerialized AccountAddress)
    summary SummaryId
    deriving Eq Show

  ContractEntry sql=cti
    index ContractIndex
    subindex ContractSubindex
    summary SummaryId
    deriving Eq Show
  |]
