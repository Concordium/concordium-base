.. _contract-module:

===================================
Smart contract module
===================================

Smart contracts are deployed on chain in *smart contract modules*.

.. note::
    A smart contract module is often referred to as *module*.

A module can contain one or more smart contracts, allowing code to be shared
among the contracts and can optionally contain :ref:`contract schemas
<contract-schema>`.

.. graphviz::
    :align: center
    :caption: A smart contract module containing two smart contracts.

    digraph G {
        subgraph cluster_0 {
            node [fillcolor=white, shape=note]
            label = "Module";
            "Crowdfunding";
            "Escrow";
        }
    }

The module must be self-contained, and only have a restricted list of imports
that allow for interaction with the chain.
These are provided by the host environment and are available for the smart
contract by importing a module named ``concordium``.

.. seealso::
    Check out :ref:`host-functions` for a complete reference.

On chain language
=================

On the Concordium blockchain the smart contract language is `Web Assembly`_
(Wasm in short), which is designed to be a portable compilation target and to be
run in sandboxed environments.
This is perfect, since smart contracts will be run by bakers in the network, who
does not necessarily trust the code.

Wasm is a low-level language and is impractical to write by hand for any
decent sized smart contracts.
Instead one would write the smart contract in a more high level language, which
is then compiled to Wasm.

Limitations
-----------

Floating point numbers
^^^^^^^^^^^^^^^^^^^^^^

Although Wasm have support floating point numbers, a smart contract is
disallowed to use them.
It is even disallowed for the Wasm module to contain a floating point number
type, which would reject the module during validation.

The reasoning behind, is that manipulating floating point numbers in Wasm is
not fully deterministic.
This could introduce problems for reaching consensus in the blockchain, as
nodes reach different conclusions.

Deployment
==========

Deploying a module to the chain, essentially means getting the module bytecode
in a block on the chain.

A module is deployed onto the chain in the form of a single Wasm module, as part
of a special transaction.

.. note::

    This means the cost of deploying a smart contract is affected by the size of the
    Wasm module and the module is limited to the maximum size of a single
    transaction.

The deployment itself does not trigger any of the user-defined behavior in a
smart contract and a user must first create an *instance* of a contract.

.. seealso::

    See :ref:`contract-instances` for more on this.

Smart contract on chain
=======================

A smart contract on chain is a collection of functions exported from a deployed
module.
A smart contract must export one function for initializing instances and can
export zero or more functions for interacting with an instance.

Since a smart contract module can export functions for multiple different smart
contract, we associate the functions using a naming scheme:

- ``init_<contract-name>``: The function for initializing a smart contract must
  start with ``init_`` followed by a name of the smart contract.

- ``receive_<contract-name>_<receive-function-name>``: Functions for interacting
  with a smart contract are prefixed with ``receive_``, followed by the contract
  name and a name for the function.

.. note::
    If you develop smart contracts using Rust and ``concordium-sc-base``, the
    procedural macros ``#[init(...)]`` and ``#[receive(...)]`` sets up the
    correct naming scheme.

.. _Web Assembly: https://webassembly.org/
