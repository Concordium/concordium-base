====================================
Introduction to Smart Contracts
====================================

A smart contract is a user-supplied piece of code that can be deployed on the
chain.
It can hold state, interact with the chain, receive, hold, and send GTU tokens
and interact with other smart contracts.

Smart contracts are used to define behavior that is not directly available
on the chain.
This could be legal agreements and contracts, such as crowdfunding and
escrow contracts.

Deploying a smart contract to the chain, essentially means getting the code
into a block on chain and the deployment itself will not trigger any actions
from the smart contract.

.. note::
    The code which is on chain is referred to as the *smart contract*.

To use a smart contract, one must first create an *instance* of it, which
invokes an ``init`` message defined as part of the smart contract, setting the
initial state of that instance.
This instance is given an address, which is used by users and other smart
contract instances to invoke different ``receive`` messages also defined in the
smart contract.

Since a smart contract instance can receive, hold and send GTU tokens, it also
holds a balance.

On the Concordium blockchain the smart contract language is `Web Assembly`_
(Wasm in short), which is designed to be a portable compilation target and to
be run in sandboxed environments.
This is perfect, since the smart contracts will be run by nodes in the network.

Wasm is a very low-level language and is impractical to write by hand for any
decent sized smart contracts.
Instead one would write the smart contract in a more high level language, which
is then compiled to Wasm.

.. note::
    So far the only high level language, with official tools and libraries for
    Concordium smart contracts is Rust_, see :ref:`writing-smart-contracts` for
    more.

.. _Web Assembly: https://webassembly.org/
.. _Rust: https://www.rust-lang.org/
