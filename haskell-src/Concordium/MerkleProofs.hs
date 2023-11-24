{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TemplateHaskell #-}

module Concordium.MerkleProofs where

import Control.Applicative
import Control.Monad
import Control.Monad.Error.Class
import Control.Monad.State
import Data.Bits
import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as Builder
import qualified Data.HashMap.Strict as HM
import qualified Data.Serialize as S
import Data.Word
import Lens.Micro.Platform

import qualified Concordium.Crypto.SHA256 as SHA256
import qualified Data.FixedByteString as FBS
import Data.Maybe

-- | A generic Merkle proof is represented as a sequence of branches, each of which can be raw
--  bytes or a sub-proof. The root has for a proof can be calculated by first calculating the
--  hashes of any sub-proofs, then concatenating all the bytes together (where each subproof
--  is replaced by the byte representation of its hash), and finally computing the SHA-256 hash
--  of the byte string.
--
--  Note that a 'MerkleProof' can contain multiple 'RawData' chunks in sequence, which is equivalent
--  to a single 'RawData' chunk with the 'BS.ByteString's concatenated. It can also contain
--  'RawData' chunks with zero-length 'BS.ByteString's, which can always be omitted to produce an
--  equivalent 'MerkleProof'. For storage and transmission, compact representations should be
--  preferred, but functions operating on 'MerkleProof's should tolerate all representations.
--
--  This representation is broadly agnostic to what the proof represents, which will depend on
--  the structure of the original Merkle tree. Moreover, a 'MerkleProof' allows multiple paths
--  to be revealed in the same proof.
type MerkleProof = [MerkleBranch]

-- | A branch in a Merkle proof.
data MerkleBranch = RawData BS.ByteString | SubProof MerkleProof
    deriving (Show)

isEmpty :: MerkleProof -> Bool
isEmpty [] = True
isEmpty (RawData bytes : rest) = BS.null bytes && isEmpty rest
isEmpty _ = False

toRootHash :: MerkleProof -> SHA256.Hash
toRootHash l = SHA256.hashLazy $ Builder.toLazyByteString $ mconcat $ merkleBuilder <$> l

merkleBuilder :: MerkleBranch -> Builder.Builder
merkleBuilder (RawData bytes) = Builder.byteString bytes
merkleBuilder (SubProof sp) = Builder.shortByteString (SHA256.hashToShortByteString $ toRootHash sp)

data MerkleData
    = -- | A byte string of the given fixed length.
      FixedLengthBytes Word64
    | -- | A variable length string of bytes prefixed by its length, encoded big-endian as a
      --  fixed number of bytes.
      VariableLengthBytesBE Word8
    deriving (Show)

type Tag = String
type Id = Int

data MerkleBody
    = LiteralBytes BS.ByteString
    | Tagged Tag MerkleData
    | Sequence [MerkleBody]
    | Choice MerkleBody MerkleBody
    | Hashed Tag Id
    | RepeatedBE Tag Word8 MerkleBody
    | LFMBTree Tag Word8 BS.ByteString MerkleBody
    deriving (Show)

option :: MerkleBody -> MerkleBody
option = Choice (LiteralBytes BS.empty)

type MerkleSchema = HM.HashMap Id MerkleBody

type PartialTree = HM.HashMap Tag PartialBranch

data PartialBranch = Leaf BS.ByteString | Node PartialTree
    deriving (Show)

data ParseError
    = UnexpectedEndOfInput
    | UnexpectedSubProof
    | Expected BS.ByteString BS.ByteString
    | UnknownSchemaId Id
    | ExpectedEndOfInput
    | Context Tag ParseError
    deriving (Show)

data Parse e r
    = TakeBytes Word64 (Parse e r)
    | Fail e
    | Done r
    | Alt (Parse e r) (Parse e r)

data ParserContext r d e a = ParserContext
    { parserInput :: d,
      parserError :: e -> r,
      parserCont :: a -> d -> (e -> r) -> r
    }

newtype Parse' r d e a = Parse' {unParse' :: ParserContext r d e a -> r}

instance Functor (Parse' r d e) where
    fmap f (Parse' z) = Parse' (\ParserContext{..} -> z ParserContext{parserCont = parserCont . f, ..})

instance Applicative (Parse' r d e) where
    pure res = Parse' $ \ParserContext{..} -> parserCont res parserInput parserError
    m1 <*> m2 = m1 >>= (\x1 -> m2 >>= (pure . x1))

instance Monad (Parse' r d e) where
    Parse' a >>= cont =
        Parse'
            ( \ParserContext{..} ->
                a
                    ParserContext
                        { parserCont =
                            \x inp err ->
                                unParse'
                                    (cont x)
                                    ParserContext
                                        { parserInput = inp,
                                          parserError = err,
                                          parserCont
                                        },
                          ..
                        }
            )

-- | Try to parse with the first parser, falling back to the second on a failure.
--  If both parsers fail, the error from the first parser is used.
(<<|>) :: Parse' r d e a -> Parse' r d e a -> Parse' r d e a
Parse' a <<|> Parse' b = Parse' $ \pc ->
    a pc{parserError = \e -> b pc{parserError = \_ -> parserError pc e}}

(<|>>) :: Parse' r d e a -> Parse' r d e a -> Parse' r d e a
Parse' a <|>> Parse' b = Parse' $ \pc ->
    a pc{parserError = \_ -> b pc}

instance (Monoid e) => Alternative (Parse' r d e) where
    empty = Parse' $ \pc -> parserError pc mempty
    Parse' a <|> Parse' b = Parse' $ \pc ->
        a pc{parserError = \e1 -> b pc{parserError = \e2 -> parserError pc (e1 <> e2)}}

instance MonadError e (Parse' r d e) where
    throwError e = Parse' $ \pc -> parserError pc e
    catchError (Parse' tryBlock) catchBlock = Parse' $ \pc ->
        tryBlock (pc{parserError = \e -> unParse' (catchBlock e) pc})

addErrorContext :: (e -> e) -> Parse' r d e a -> Parse' r d e a
addErrorContext f (Parse' a) = Parse' $ \pc -> a pc{parserError = parserError pc . f}

parseBytes :: Int -> Parse' r MerkleProof ParseError BS.ByteString
parseBytes len0 = Parse' $ \ParserContext{..} -> inner parserError len0 parserInput parserCont
  where
    inner parserError 0 inp cont = cont BS.empty inp parserError
    inner parserError _ [] _ = parserError UnexpectedEndOfInput
    inner parserError len (RawData bytes : rest) cont = case compare (BS.length bytes) len of
        LT -> inner parserError (len - BS.length bytes) rest (cont . (bytes <>))
        EQ -> cont bytes rest parserError
        GT -> let (b0, b1) = BS.splitAt len bytes in cont b0 (RawData b1 : rest) parserError
    inner parserError _ (SubProof _ : _) _ = parserError UnexpectedSubProof

-- parseSubProof :: Parse' r MerkleProof ParseError a -> Parse' r MerkleProof ParseError a
-- parseSubProof = Parse' $ \ParserContext{..} -> case parserInput of
--     [] -> parserError UnexpectedEndOfInput

parseSubProof ::
    Parse' r MerkleProof ParseError (a, Builder.Builder) ->
    Parse' r [MerkleBranch] ParseError (SHA256.Hash, Maybe a)
parseSubProof inside = Parse' $ \pc@ParserContext{..} -> case parserInput of
    [] -> parserError UnexpectedEndOfInput
    (RawData bs : rest)
        | BS.null bs -> unParse' (parseSubProof inside) pc{parserInput = rest}
        | otherwise ->
            unParse'
                ( do
                    bytes <- parseBytes 32
                    let hsh = SHA256.Hash (FBS.fromByteString bytes)
                    return (hsh, Nothing)
                )
                pc
    (SubProof sp : rest) ->
        unParse'
            inside
            pc
                { parserInput = sp,
                  parserCont = \(subPT, builder) remaining onErr ->
                    if isEmpty remaining
                        then
                            let hsh = hashBuilder builder
                            in  parserCont
                                    (hsh, Just subPT)
                                    rest
                                    parserError
                        else onErr ExpectedEndOfInput
                }

parseMerkleBody :: MerkleSchema -> MerkleBody -> PartialTree -> Parse' r MerkleProof ParseError (PartialTree, Builder.Builder)
parseMerkleBody schema = inner
  where
    inner (LiteralBytes expect) pt = do
        actual <- parseBytes (BS.length expect)
        unless (expect == actual) $ throwError (Expected expect actual)
        return (pt, Builder.byteString actual)
    inner (Tagged tag (FixedLengthBytes len)) pt = addErrorContext (Context tag) $ do
        bytes <- parseBytes (fromIntegral len)
        return (HM.insert tag (Leaf bytes) pt, Builder.byteString bytes)
    inner (Tagged tag (VariableLengthBytesBE lenSize)) pt = addErrorContext (Context tag) $ do
        lenBytes <- parseBytes (fromIntegral lenSize)
        let len = BS.foldl' (\acc w -> acc * 256 + fromIntegral w) 0 lenBytes
        bytes <- parseBytes len
        return (HM.insert tag (Leaf bytes) pt, Builder.byteString lenBytes <> Builder.byteString bytes)
    inner (Sequence l) pt = do
        let f (pt', builder) mb = do
                (pt'', builder'') <- inner mb pt'
                return (pt'', builder <> builder'')
        foldM f (pt, mempty) l
    inner (Choice a b) pt = inner a pt <<|> inner b pt
    inner (Hashed tag ident) pt = addErrorContext (Context tag) $ case HM.lookup ident schema of
        Nothing -> throwError (UnknownSchemaId ident)
        Just body -> do
            (subHash, mbranch) <- parseSubProof (inner body mempty)
            let hashBS = SHA256.hashToByteString subHash
                val = case mbranch of
                    Nothing -> Leaf hashBS
                    Just branch -> Node branch
            return (HM.insert tag val pt, Builder.byteString hashBS)
    inner (RepeatedBE tag lenSize sub) pt = addErrorContext (Context tag) $ do
        lenBytes <- parseBytes (fromIntegral lenSize)
        let len = fromBE lenBytes
        let f (pt', builder) i = addErrorContext (Context (show i)) $ do
                (pt'', builder'') <- inner sub mempty
                return (HM.insert (show i) (Node pt'') pt', builder <> builder'')
        (pt1, builder) <- foldM f (mempty, mempty) [0 .. (len :: Integer) - 1]
        return (HM.insert tag (Node pt1) pt, builder)
    inner (LFMBTree tag lenSize emptyBS sub) pt0 = addErrorContext (Context tag) $ do
        lenBytes <- parseBytes (fromIntegral lenSize)
        let len = fromBE lenBytes
        let doTree 0 _ pt = do
                actual <- parseBytes (BS.length emptyBS)
                unless (actual == emptyBS) $ throwError (Expected emptyBS actual)
                return (pt, SHA256.hash emptyBS)
            doTree 1 base pt = do
                (pt1, bs) <- inner sub mempty
                return (HM.insert (show base) (Node pt1) pt, hashBuilder bs)
            doTree size base pt = do
                let leftSize = lowerPowerOfTwo size
                (pt1, h1) <- doBranch leftSize base pt
                (pt2, h2) <- doBranch (size - leftSize) (base + leftSize) pt1
                return (pt2, SHA256.hashOfHashes h1 h2)
            doBranch size base pt = do
                (hsh, msubProof) <- parseSubProof ((_2 %~ builderHash) <$> doTree size base pt)
                return (fromMaybe pt msubProof, hsh)
        (ptSub, hsh) <- doBranch len 0 mempty
        return (HM.insert tag (Node ptSub) pt0, builderHash hsh)

hashBuilder :: Builder.Builder -> SHA256.Hash
hashBuilder = SHA256.hashLazy . Builder.toLazyByteString

builderHash :: SHA256.Hash -> Builder.Builder
builderHash = Builder.shortByteString . SHA256.hashToShortByteString

fromBE :: (Num a) => BS.ByteString -> a
fromBE = BS.foldl' (\acc w -> acc * 256 + fromIntegral w) 0

-- | Compute the nearest power of 2 less than the input value.
--
-- PRECONDITION: The input is at least 2.
lowerPowerOfTwo :: Word64 -> Word64
lowerPowerOfTwo x
    | x < 2 = error "lowerPowerOfTwo: input must be at least 2"
    | otherwise = bit (finiteBitSize x - countLeadingZeros (x - 1) - 1)

parseMerkleProof :: MerkleSchema -> Id -> MerkleProof -> Either ParseError (PartialTree, SHA256.Hash)
parseMerkleProof schema ident pf = case HM.lookup ident schema of
    Nothing -> Left (UnknownSchemaId ident)
    Just body ->
        unParse'
            (parseMerkleBody schema body HM.empty)
            ParserContext{parserInput = pf, parserError = Left, parserCont = cont}
  where
    cont (pt, builder) remaining onErr
        | isEmpty remaining = Right (pt, hashBuilder builder)
        | otherwise = onErr ExpectedEndOfInput

data SchemaBuilderState = SchemaBuilderState
    { _builderSchema :: !MerkleSchema,
      _builderNextIdent :: !Id
    }

makeLenses ''SchemaBuilderState

emptySchemaBuilderState :: SchemaBuilderState
emptySchemaBuilderState = SchemaBuilderState HM.empty 0

freshIdent :: (MonadState SchemaBuilderState m) => m Id
freshIdent = builderNextIdent <<%= (+ 1)

schemaAt :: Id -> Lens' SchemaBuilderState (Maybe MerkleBody)
schemaAt ident = builderSchema . at ident

setFresh :: (MonadState SchemaBuilderState m) => MerkleBody -> m Id
setFresh body = do
    newIdent <- freshIdent
    schemaAt newIdent ?= body
    return newIdent

setFreshRec :: (MonadState SchemaBuilderState m) => (Id -> MerkleBody) -> m Id
setFreshRec body = do
    newIdent <- freshIdent
    schemaAt newIdent ?= body newIdent
    return newIdent

blockSchema :: (Id, MerkleSchema)
blockSchema = runState builder emptySchemaBuilderState & _2 %~ _builderSchema
  where
    u64 = FixedLengthBytes 8
    node l = Sequence [Hashed tag ident | (tag, ident) <- l]
    opaqueHash = FixedLengthBytes 32
    builder = do
        blockHash <- freshIdent
        blockHeaderHash <-
            setFresh . Sequence $
                [ Tagged "round" u64,
                  Tagged "epoch" u64,
                  Hashed "parent" blockHash
                ]
        timestampBakerHash <- setFresh . Sequence $ [Tagged "timestamp" u64, Tagged "bakerId" u64]
        nonceHash <- setFresh $ Tagged "blockNonce" (FixedLengthBytes 80)
        bakerInfoHash <- setFresh . node $ [("timestampBaker", timestampBakerHash), ("nonce", nonceHash)]
        quorumCertificateHash <-
            setFresh . Sequence $
                [ Hashed "block" blockHash,
                  Tagged "round" u64,
                  Tagged "epoch" u64,
                  Tagged "aggregateSignature" (FixedLengthBytes 48),
                  Tagged "signatories" (VariableLengthBytesBE 4)
                ]
        timeoutCertificateHash <-
            setFresh $
                Choice
                    ( Sequence
                        [ LiteralBytes (S.encode (0 :: Word8)),
                          Tagged "null" (FixedLengthBytes 0)
                        ]
                    )
                    ( Sequence
                        [ LiteralBytes (S.encode (1 :: Word8)),
                          Tagged "round" u64,
                          Tagged "minEpoch" u64,
                          RepeatedBE "finalizerQCRoundsFirstEpoch" 4 $
                            Sequence
                                [ Tagged "round" u64,
                                  Tagged "finalizers" (VariableLengthBytesBE 4)
                                ],
                          RepeatedBE "finalizerQCRoundsSecondEpoch" 4 $
                            Sequence
                                [ Tagged "round" u64,
                                  Tagged "finalizers" (VariableLengthBytesBE 4)
                                ],
                          Tagged "aggregateSignature" (FixedLengthBytes 48)
                        ]
                    )
        epochFinalizationEntryHash <-
            setFresh $
                Choice
                    ( Sequence
                        [ LiteralBytes (S.encode (0 :: Word8)),
                          Tagged "null" (FixedLengthBytes 0)
                        ]
                    )
                    ( Sequence
                        [ LiteralBytes (S.encode (1 :: Word8)),
                          Hashed "finalizedBlock" blockHash,
                          Tagged "finalizedRound" u64,
                          Tagged "epoch" u64,
                          Tagged "finalizedAggregateSignature" (FixedLengthBytes 48),
                          Tagged "finalizedSignatories" (VariableLengthBytesBE 4),
                          Tagged "successorAggregateSignature" (FixedLengthBytes 48),
                          Tagged "successorSignatories" (VariableLengthBytesBE 4),
                          Tagged "successorProof" opaqueHash
                        ]
                    )
        timeoutFinalizationHash <-
            setFresh . Sequence $
                [ Hashed "timeoutCertificate" timeoutCertificateHash,
                  Hashed "epochFinalizationEntry" epochFinalizationEntryHash
                ]
        certificatesHash <-
            setFresh . node $
                [ ("quorumCertificate", quorumCertificateHash),
                  ("timeoutFinalization", timeoutFinalizationHash)
                ]
        metaHash <- setFresh . node $ [("bakerInfo", bakerInfoHash), ("certificatesHash", certificatesHash)]
        transactionsAndOutcomesHash <-
            setFresh . Sequence $
                [ Tagged "transactions" opaqueHash,
                  Tagged "outcomes" opaqueHash
                ]
        dataHash <-
            setFresh . Sequence $
                [ Hashed "transactionsAndOutcomes" transactionsAndOutcomesHash,
                  Tagged "state" opaqueHash
                ]
        blockQuasiHash <- setFresh . Sequence $ [Hashed "meta" metaHash, Hashed "data" dataHash]
        schemaAt blockHash ?= Sequence [Hashed "header" blockHeaderHash, Hashed "quasi" blockQuasiHash]
        return blockHash

rawHash :: BS.ByteString -> MerkleBranch
rawHash = RawData . S.encode . SHA256.hash

testProof1 :: [MerkleBranch]
testProof1 =
    [ SubProof [RawData $ S.runPut (S.putWord64be 2 >> S.putWord64be 0 >> S.put (SHA256.hash ""))],
      rawHash "asb"
    ]

testProof2 :: [MerkleBranch]
testProof2 =
    [ rawHash "abc",
      SubProof
        [ SubProof
            [ SubProof
                [ SubProof
                    [ RawData . S.runPut $ do
                        -- Timestamp
                        S.putWord64be 123456
                        -- BakerID
                        S.putWord64be 256
                    ],
                  rawHash "asdf"
                ],
              rawHash "qwerty"
            ],
          rawHash "asdff"
        ]
    ]

testProof3 :: [MerkleBranch]
testProof3 =
    [ SubProof [RawData $ S.runPut (S.putWord64be 2 >> S.putWord64be 0 >> S.put (SHA256.hash ""))],
      SubProof
        [ SubProof
            [ SubProof
                [ SubProof
                    [ RawData . S.runPut $ do
                        -- Timestamp
                        S.putWord64be 123456
                        -- BakerID
                        S.putWord64be 256
                    ],
                  rawHash "asdf"
                ],
              rawHash "qwerty"
            ],
          rawHash "asdff"
        ]
    ]

testProof4 :: [MerkleBranch]
testProof4 =
    [ SubProof
        [ RawData "\NUL\NUL\NUL\NUL\NUL)K_\NUL\NUL\NUL\NUL\NUL\NUL\180\148\238\SO\182yU/\249\ENQ\169[\235\206\129\SYNdQP6s\NUL\SOH\ENQ\219\STX`\250\157d\239\ESC\255\128"
        ],
      SubProof
        [ SubProof
            [ SubProof
                [ SubProof [RawData "\NUL\NUL\SOH\139\164\234r\CAN\NUL\NUL\NUL\NUL\NUL\NUL\NUL\STX"],
                  SubProof
                    [ SubProof [RawData "D\SUB\142D\133\247\168\237\212M\251\176\153\229\STX\244\175\&6\202\218\144:u\226\207\US\196\133\194tH\132\149D\SOH]\vz\217\147SR\147U\196\242\242\220%u!\DC2~\RS\187\STX\b\234\180\SI\163\227\SUB\182h\226/\173\179rF_\ENQ\157\203\b \SI\207\a"]
                    ]
                ],
              SubProof
                [ SubProof
                    [RawData "\238\SO\182yU/\249\ENQ\169[\235\206\129\SYNdQP6s\NUL\SOH\ENQ\219\STX`\250\157d\239\ESC\255\128\NUL\NUL\NUL\NUL\NUL)K^\NUL\NUL\NUL\NUL\NUL\NUL\180\147\130\199\202\NAKn\DC4K\140)\STX=\167\134/\242c\249Z\168\133\SI\143\tmP<e\214\173\131\220\239\191,\232\224\230`\US\ETB\181\165\208\156\210\ESCX\166\NUL\NUL\NUL\SOH\GS"],
                  SubProof
                    [ SubProof [RawData "\NUL"],
                      SubProof [RawData "\SOH/\ENQ\ENQ\201\131.\132Hl\171\&7\245\179\198\134\226\236\183\252j\NAKc\130\246\218\162\ACKL\152\&9\rA\NUL\NUL\NUL\NUL\NUL)K]\NUL\NUL\NUL\NUL\NUL\NUL\180\147\173R\225\NUL\193\FS\194\SI\255_\246\185\156\a\bJ\203\199\240_\147\231\SUB\177\222Z\225Q\v\170X\135o\213B\199J\249\186\138~\188\155Lb\146\222\249\NUL\NUL\NUL\SOH\ETB\130\199\202\NAKn\DC4K\140)\STX=\167\134/\242c\249Z\168\133\SI\143\tmP<e\214\173\131\220\239\191,\232\224\230`\US\ETB\181\165\208\156\210\ESCX\166\NUL\NUL\NUL\SOH\GS@\235\213\&0\157H\233\216f]\247\141\173O\235\235\&2\149(C\138\254]\221@!6\159\EM\133\245\219"]
                    ]
                ]
            ],
          SubProof
            [ SubProof
                [ SubProof [RawData "\227\176\196B\152\252\FS\DC4\154\251\244\200\153o\185$'\174A\228d\155\147L\164\149\153\ESCxR\184U"],
                  SubProof [RawData "\ENQ[}H\222.w\136\t\227\&6\224q\US\188\240b\SYN\188\231\158\ESC>\152\167\179\EOTE\CAN\170\DLE\197"]
                ],
              SubProof [RawData "\RSp\GS(\251\191\221\157\185\247\&2\214L\151zt\254\DC1\148r\225\215\199\184\148\ACK\210\148\ACK\159\244\212"]
            ]
        ]
    ]

class MerkleProvable m t where
    buildMerkleProof :: ([Tag] -> Bool) -> t -> m MerkleProof
