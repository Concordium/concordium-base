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
testingBlockHash = read "9926f53cde0d3f25afb2dd9f3eb4050da1b01940c501a3c5d22719535061f95a"

-- | A Merkle proof against the testing block.
--  This proof should follow the block schema, and parse into 'testingBlockTree'.
testingBlockProof :: MerkleProof
testingBlockProof =
    [ SubProof
        [ RawData "\NUL\NUL\NUL\NUL\NUL\NUL\NUL\SOH\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NULR\148Hk\211\243\144\162\198\225z\128D\NAK\146?\FS\177H'&\180Yx#3yL\byD\242"
        ],
      SubProof
        [ SubProof
            [ SubProof
                [ SubProof
                    [ RawData "\NUL\NUL\SOH\140\213;\246a\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL"
                    ],
                  SubProof
                    [ RawData "\ETB\138\244e\164\RS\b\t\242\247H\SYN\153J\234tB\SOH\148\170\183\235\FS\176sm\149\bCA\242\FS\195\197\147o\244U@P\228j<\ETBr\228\205\134\SON&\142-++\132\205\134\247e\172\&7&g\179\SI:ETc\247\SI\208w\147\137\139\208\219\r"
                    ]
                ],
              SubProof
                [ SubProof
                    [ RawData "R\148Hk\211\243\144\162\198\225z\128D\NAK\146?\FS\177H'&\180Yx#3yL\byD\242\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\192\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL"
                    ],
                  SubProof
                    [ SubProof [RawData "\NUL"],
                      SubProof [RawData "\NUL"]
                    ]
                ]
            ],
          SubProof
            [ SubProof
                [ RawData "\196#\249\233\RS\226\CAN\178\181\&04\133\221\135\163\t:e=\219\155\219\131\157\&0\170\EM$\222\GS\191\ENQ4^\248\197{3\154E[q\231\184\190\245g\157\197\162P`\141\ETX\251M-\225\234\208\200\\\CAN>"
                ],
              RawData "\149\238']~\245\167\a\130\DC2\251\ENQ\177S\255\240\243B\251\RS\203t\168\245B\162\152\233\161\160#\GS"
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
                      ("parent", Leaf "R\148Hk\211\243\144\162\198\225z\128D\NAK\146?\FS\177H'&\180Yx#3yL\byD\242"),
                      ("round", Leaf "\NUL\NUL\NUL\NUL\NUL\NUL\NUL\SOH")
                    ]
                )
            ),
            ( "quasi",
              Node
                ( HM.fromList
                    [   ( "data",
                          Node
                            ( HM.fromList
                                [   ( "transactionsAndOutcomes",
                                      Node
                                        ( HM.fromList
                                            [ ("outcomes", Leaf "4^\248\197{3\154E[q\231\184\190\245g\157\197\162P`\141\ETX\251M-\225\234\208\200\\\CAN>"),
                                              ("transactions", Leaf "\196#\249\233\RS\226\CAN\178\181\&04\133\221\135\163\t:e=\219\155\219\131\157\&0\170\EM$\222\GS\191\ENQ")
                                            ]
                                        )
                                    ),
                                  ("state", Leaf "\149\238']~\245\167\a\130\DC2\251\ENQ\177S\255\240\243B\251\RS\203t\168\245B\162\152\233\161\160#\GS")
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
                                                          ("timeoutCertificate", Node (HM.fromList [("null", Leaf "")]))
                                                        ]
                                                    )
                                                ),
                                                ( "quorumCertificate",
                                                  Node
                                                    ( HM.fromList
                                                        [ ("epoch", Leaf "\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL"),
                                                          ("block", Leaf "R\148Hk\211\243\144\162\198\225z\128D\NAK\146?\FS\177H'&\180Yx#3yL\byD\242"),
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
                                                        [ ("blockNonce", Leaf "\ETB\138\244e\164\RS\b\t\242\247H\SYN\153J\234tB\SOH\148\170\183\235\FS\176sm\149\bCA\242\FS\195\197\147o\244U@P\228j<\ETBr\228\205\134\SON&\142-++\132\205\134\247e\172\&7&g\179\SI:ETc\247\SI\208w\147\137\139\208\219\r")
                                                        ]
                                                    )
                                                ),
                                                ( "timestampBaker",
                                                  Node
                                                    ( HM.fromList
                                                        [ ("bakerId", Leaf "\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL"),
                                                          ("timestamp", Leaf "\NUL\NUL\SOH\140\213;\246a")
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
