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

-- We deliberately do not derive automatic migration here since it leads to
-- suboptimal indices. Instead we manually create the database when needed in
-- the node. If the types of columns/tables change we will have to provide a
-- manual migration path for it.
share [mkPersist sqlSettings] [persistLowerCase|
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
