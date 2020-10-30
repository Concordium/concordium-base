.. _contracts-on-chain:

===================================
Smart contracts on the chain
===================================

In this section we describe all aspects of smart contracts on the chain.
This is especially relevant for a node in the network.

Life-cycle
===================================

The following operations are possible for smart contracts.

- Deploy a smart contract module.
- Initialize a smart contract instance from a deployed smart contract.
- Invoke an existing smart contract instance with a specific message.
  This can be done repeatedly and can both update the state and the GTU amount
  on the smart contract instance, as well as send messages to other smart
  contract instances.

All of these actions are done as transactions that are sent by accounts,
recorded in blocks, and paid for by the sender of the transaction.

Smart contract module
===================================

.. graphviz::
    :align: center
    :caption: Example of smart contract module containing two smart contracts:
              Escrow and Crowdfunding. Each contract have two instances.

    digraph G {
        node [style=filled, color = white]

        subgraph cluster_0 {
            label = "Smart contract module";
            style=filled;
            color=lightgrey;
            "Crowdfunding";
            "Escrow";
        }

        subgraph cluster_1 {
            label = "Instances";
            style=filled;
            color=lightgrey;
            House;
            Car;
            Gadget;
            Boardgame;
        }

        Escrow:s -> House;
        Escrow:s -> Car;
        Crowdfunding:s -> Gadget;
        Crowdfunding:s -> Boardgame;
    }

A *smart contract module* can contain the code for one or more smart contracts,
allowing code to be shared between the contracts.
It is deployed onto the chain as a single Wasm module, as part of a single
transaction.

.. note::
    This means the cost of deploying a smart contract is affected by the size of
    the Wasm module and the module is limited to the maximum size of a single
    transaction.

The module must be self-contained, and only have a restricted list of imports
that interact with the chain.
These are provided by the host environment and are available for the smart
contract by importing a module named ``concordium``.

.. seealso::
    Check out :ref:`host-functions` for a complete reference.

Instantiating a smart contract
==============================
The smart contract module can export several functions, some for creating smart
contract instances.
To instantiate a smart contract, an account sends a special transaction with
the information of where to find the smart contract on chain and which function
from the module to use for creating an instance.

.. note::
    The functions for creating a new instance are referred to as
    ``init``-functions.

This function can take an argument, which is also supplied as part of the
transaction.
The transaction can also include an amount of GTU, which is added to the
balance of the smart contract instance.
If the ``init``-function is successful, it returns the initial state of the
instance.

There are only *one* ``init``-function for each *smart contract*, but a
*smart contract module* can contain multiple smart contracts.
If need of different variations of some smart contract, one can either define
an ``init``-function for each variation, resulting in multiple smart contracts
or use the parameter to change the behavior.
This is up to the developer of the contract.

Interacting with an instance
============================

A smart contract module include functions for interacting with a smart contract
instance.

.. note::
    Functions for interacting with a smart contract instance are referred to as
    ``receive``-functions.

Just like with ``init``-functions, these are triggered using transactions,
which may contain some amount of GTU for the contract and an argument used by
the function.

A ``receive``-function returns a description of actions, that it would like to
be executed on chain.
The function can read and write the state of a smart contract instance and
access information about the chain.

.. todo::
    Link section about accessible chain information.

Instance state
==============
A smart contract instance is able to hold state.
The state is simply an array of bytes and the instance uses functions supplied
by the host environment to read and write.

.. seealso::
    See :ref:`host-functions-state` for the reference of these functions.

Floating point numbers
======================
Although Wasm have support floating point numbers, a smart contract is
disallowed to use them.
It is even disallowed for the Wasm module to contain a floating point number
type, which would reject the module during validation.

The reasoning behind, is that manipulating floating point numbers in Wasm is
not fully deterministic.
This could introduce problems for reaching consensus in the blockchain, as
nodes reach different conclusions.
