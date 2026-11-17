{-# LANGUAGE DataKinds #-}

-- | Fixed chain-parameter examples shared by serialization tests.
module Examples.ChainParameters (p8ChainParametersExample, p11ChainParametersExample) where

import Data.Ratio ((%))

import Concordium.Types
import Concordium.Types.Parameters

-- | Fixed P8 parameters for historical wire and hash compatibility tests.
p8ChainParametersExample :: ChainParameters 'P8
p8ChainParametersExample =
    ChainParameters
        { _cpConsensusParameters =
            ConsensusParametersV1
                { _cpTimeoutParameters = TimeoutParameters 10000 (2 % 1) (4 % 5),
                  _cpMinBlockTime = 1000,
                  _cpBlockEnergyLimit = 1000000
                },
          _cpExchangeRates = makeExchangeRates (1 / 10000) 1000000,
          _cpCooldownParameters = CooldownParametersV1 3600 7200,
          _cpTimeParameters = SomeParam (TimeParametersV1 2 (MintRate 1 8)),
          _cpAccountCreationLimit = 10,
          _cpRewardParameters =
            RewardParameters
                { _rpMintDistribution =
                    MintDistribution CFalse (makeAmountFraction 60000) (makeAmountFraction 30000),
                  _rpTransactionFeeDistribution =
                    TransactionFeeDistribution (makeAmountFraction 45000) (makeAmountFraction 45000),
                  _rpGASRewards =
                    GASRewards
                        (makeAmountFraction 25000)
                        CFalse
                        (makeAmountFraction 200)
                        (makeAmountFraction 50)
                },
          _cpFoundationAccount = 0,
          _cpPoolParameters =
            PoolParametersV1
                { _ppPassiveCommissions =
                    CommissionRates
                        (makeAmountFraction 10000)
                        (makeAmountFraction 5000)
                        (makeAmountFraction 5000),
                  _ppCommissionBounds =
                    CommissionRanges
                        (InclusiveRange (makeAmountFraction 0) (makeAmountFraction 100000))
                        (InclusiveRange (makeAmountFraction 0) (makeAmountFraction 100000))
                        (InclusiveRange (makeAmountFraction 0) (makeAmountFraction 100000)),
                  _ppMinimumEquityCapital = 300000000000,
                  _ppCapitalBound = CapitalBound (makeAmountFraction 10000),
                  _ppLeverageBound = 5
                },
          _cpFinalizationCommitteeParameters =
            SomeParam (FinalizationCommitteeParameters 50 500 (PartsPerHundredThousands 10000)),
          _cpValidatorScoreParameters = SomeParam (ValidatorScoreParameters 1),
          _cpMaxLockDuration = NoParam
        }

-- | P11 parameters with the same shared values and a required duration.
p11ChainParametersExample :: ChainParameters 'P11
p11ChainParametersExample =
    let ChainParameters{..} = p8ChainParametersExample
    in  ChainParameters
            { _cpConsensusParameters = _cpConsensusParameters,
              _cpExchangeRates = _cpExchangeRates,
              _cpCooldownParameters = _cpCooldownParameters,
              _cpTimeParameters = SomeParam (unOParam _cpTimeParameters),
              _cpAccountCreationLimit = _cpAccountCreationLimit,
              _cpRewardParameters = case _cpRewardParameters of RewardParameters{..} -> RewardParameters{..},
              _cpFoundationAccount = _cpFoundationAccount,
              _cpPoolParameters = _cpPoolParameters,
              _cpFinalizationCommitteeParameters = SomeParam (unOParam _cpFinalizationCommitteeParameters),
              _cpValidatorScoreParameters = SomeParam (unOParam _cpValidatorScoreParameters),
              _cpMaxLockDuration = SomeParam (Duration 42)
            }
