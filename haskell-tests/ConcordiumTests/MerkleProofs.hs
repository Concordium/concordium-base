{-# LANGUAGE OverloadedStrings #-}

-- | Simple unit tests for Merkle proofs.
--  These tests check that a given Merkle proof hashes and parses to known results.
--  This is not intended as a comprehensive test of the Merkle proof functionality.
--  Rather, the proof parsing infrastructure is intended to be used to test the correct
--  production of Merkle proofs in the node.
module ConcordiumTests.MerkleProofs where

import qualified Data.HashMap.Strict as HM
import Test.Hspec

import qualified Concordium.Crypto.SHA256 as Hash
import Concordium.MerkleProofs

-- | Block hash of testing block.
testingBlockHash :: Hash.Hash
testingBlockHash = read "c2b97dbfafa2de205dad08053ecbf35ba0ee8e918c79dbab0b2c27256fb02e38"

-- | A Merkle proof against the testing block.
--  This proof should follow the block schema, and parse into 'testingBlockTree'.
testingBlockProof :: MerkleProof
testingBlockProof =
    [ SubProof
        [RawData "\NUL\NUL\NUL\NUL\NUL\NUL\NUL\STX\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\228\167\238\197\135\145D:\197{\224\211\200\199\ACK\FS\225\184+\RS\185\SUBn$\185\DELVg\130\&9\160^"],
      SubProof
        [ SubProof
            [ SubProof
                [ SubProof [RawData "\NUL\NUL\NUL\NUL\NUL\NUL\a\208\NUL\NUL\NUL\NUL\NUL\NUL\NUL\EOT"],
                  SubProof [RawData "%\174\f\194\NUL\v\213\STX\234N\152\215\&0\n\155\171q\238\144zK\141\189\161^\215\184)B \FSj\187c\138\146=B\137\149kl\240\&8_\207\154_wK\137\230\STXe\182\204\NUL\193\200MwR\251?m\193k\152\228\134\rnI\154\236\253{3\137\SOH"]
                ],
              SubProof
                [ SubProof [RawData "\228\167\238\197\135\145D:\197{\224\211\200\199\ACK\FS\225\184+\RS\185\SUBn$\185\DELVg\130\&9\160^\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\192\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL"],
                  SubProof
                    [ SubProof [RawData "\SOH\NUL\NUL\NUL\NUL\NUL\NUL\NUL\SOH\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\128\149*`3\201\&4#\191\247\rv$\vL\149\178W\140\219\n\240\DC3\161\223\157\154\243z\158\226>\b\241\199\228\"\\>\155\248\\\237\FS\222%\SI\209\NUL\NUL\NUL\SOH\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\SOH?\NUL\NUL\NUL\NUL"],
                      SubProof [RawData "\NUL"]
                    ]
                ]
            ],
          SubProof
            [ RawData "\196#\249\233\RS\226\CAN\178\181\&04\133\221\135\163\t:e=\219\155\219\131\157\&0\170\EM$\222\GS\191\ENQ",
              RawData "V\161\148\235\199\132<\236\FS=\129\245\255'\156VPV\129\SYN\RS\241\129\179t\205\f\132|\200\tf"
            ]
        ]
    ]

-- | The expected result of parsing the 'testingBlockProof'.
testingBlockTree :: PartialTree
testingBlockTree =
    HM.fromList
        [   ( "header",
              Node
                ( HM.fromList
                    [ ("epoch", Leaf "\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL"),
                      ("parent", Leaf "\228\167\238\197\135\145D:\197{\224\211\200\199\ACK\FS\225\184+\RS\185\SUBn$\185\DELVg\130\&9\160^"),
                      ("round", Leaf "\NUL\NUL\NUL\NUL\NUL\NUL\NUL\STX")
                    ]
                )
            ),
            ( "quasi",
              Node
                ( HM.fromList
                    [   ( "data",
                          Node
                            ( HM.fromList
                                [ ("result", Leaf "V\161\148\235\199\132<\236\FS=\129\245\255'\156VPV\129\SYN\RS\241\129\179t\205\f\132|\200\tf"),
                                  ("transactions", Leaf "\196#\249\233\RS\226\CAN\178\181\&04\133\221\135\163\t:e=\219\155\219\131\157\&0\170\EM$\222\GS\191\ENQ")
                                ]
                            )
                        ),
                        ( "meta",
                          Node
                            ( HM.fromList
                                [   ( "certificatesHash",
                                      Node
                                        ( HM.fromList
                                            [   ( "timeoutFinalization",
                                                  Node
                                                    ( HM.fromList
                                                        [ ("epochFinalizationEntry", Node (HM.fromList [("null", Leaf "")])),
                                                          ("timeoutCertificate", Node (HM.fromList [("finalizerQCRoundsFirstEpoch", Node (HM.fromList [("0", Node (HM.fromList [("finalizers", Leaf "?"), ("round", Leaf "\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL")]))])), ("aggregateSignature", Leaf "\128\149*`3\201\&4#\191\247\rv$\vL\149\178W\140\219\n\240\DC3\161\223\157\154\243z\158\226>\b\241\199\228\"\\>\155\248\\\237\FS\222%\SI\209"), ("round", Leaf "\NUL\NUL\NUL\NUL\NUL\NUL\NUL\SOH"), ("minEpoch", Leaf "\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL"), ("finalizerQCRoundsSecondEpoch", Node (HM.fromList []))]))
                                                        ]
                                                    )
                                                ),
                                                ( "quorumCertificate",
                                                  Node
                                                    ( HM.fromList
                                                        [ ("epoch", Leaf "\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL"),
                                                          ("block", Leaf "\228\167\238\197\135\145D:\197{\224\211\200\199\ACK\FS\225\184+\RS\185\SUBn$\185\DELVg\130\&9\160^"),
                                                          ("aggregateSignature", Leaf "\192\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL"),
                                                          ("round", Leaf "\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL"),
                                                          ("signatories", Leaf "")
                                                        ]
                                                    )
                                                )
                                            ]
                                        )
                                    ),
                                    ( "bakerInfo",
                                      Node
                                        ( HM.fromList
                                            [   ( "nonce",
                                                  Node
                                                    ( HM.fromList
                                                        [ ("blockNonce", Leaf "%\174\f\194\NUL\v\213\STX\234N\152\215\&0\n\155\171q\238\144zK\141\189\161^\215\184)B \FSj\187c\138\146=B\137\149kl\240\&8_\207\154_wK\137\230\STXe\182\204\NUL\193\200MwR\251?m\193k\152\228\134\rnI\154\236\253{3\137\SOH")
                                                        ]
                                                    )
                                                ),
                                                ( "timestampBaker",
                                                  Node
                                                    ( HM.fromList
                                                        [ ("bakerId", Leaf "\NUL\NUL\NUL\NUL\NUL\NUL\NUL\EOT"),
                                                          ("timestamp", Leaf "\NUL\NUL\NUL\NUL\NUL\NUL\a\208")
                                                        ]
                                                    )
                                                )
                                            ]
                                        )
                                    )
                                ]
                            )
                        )
                    ]
                )
            )
        ]

tests :: Spec
tests = describe "Concordium.MerkleProofs" $ do
    it "toRootHash on testing block" $ do
        -- Test that the 'testingBlockProof' hashes to the 'testingBlockHash'.
        toRootHash testingBlockProof
            `shouldBe` testingBlockHash
    it "parseMerkleProof on testing block" $ do
        -- This simply tests that 'parseMerkleProof' with the 'blockSchema' gives a known outcome
        -- on the 'testingBlockProof'. This is subject to change if the schema changes.
        uncurry parseMerkleProof blockSchema testingBlockProof
            `shouldBe` Right (testingBlockTree, testingBlockHash)
