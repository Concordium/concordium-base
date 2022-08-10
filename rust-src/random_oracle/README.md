# Using the random oracle replacement

`RandomOracle` instances should be initialized with at domain-separation string and passed to protocols by mutable borrow. Protocols should update the state of the `RandomOracle`, allowing them to be sequentially composed.

The `RandomOracle` instance used to verify a proof needs to be initialised with the context used to produce the proof. Any verification of sub-proofs needs to be performed in the same order as when producing the proof.
