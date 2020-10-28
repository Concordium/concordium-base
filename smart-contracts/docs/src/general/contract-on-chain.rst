.. _contracts-on-chain:

===================================
Smart contracts on the chain
===================================

In this section we describe all aspects of smart contracts that are relevant
for a node in the network.

Life-cycle
===================================

.. note::
    A *smart contract module* is a collection of smart contracts packaged into
    one file, allowing code sharing between contracts.

The following operations are possible for smart contracts.

- Deploy a smart contract module.
- Initialize a smart contract instance from a deployed smart contract.
- Invoke an existing smart contract instance with a specific message.
  This can be done repeatedly and can both update the state and the GTU amount
  on the smart contract instance, as well as send messages to other smart
  contract instances.

All of these actions are done as transactions that are sent by accounts,
recorded in blocks, and paid for by the sender of the transaction.



Format of smart contracts
===================================

A smart contract module is deployed onto the chain as a single Wasm
module, as part of a single transaction.
This means the cost of deploying a smart contract is affected by the size of
the Wasm module and the module is limited to the maximum size of a single
transaction.

The module must be self-contained, and only have a restricted list of imports
that interact with the chain.
These are provided by the host environment and are available in the Smart
Contract by importing a module named ``concordium``.

.. seealso::
    Check out :ref:`host-functions` for a complete reference.

The smart contract module then exports functions for creating smart contract
instances.
To call such a function and instantiate a smart contract, an account sends a
transaction with the information of where to find the smart contract on chain
and which function from the module to use for creating an instance.
This function will typically take an argument, also supplied as part of the
transaction.

.. note::
    The functions for creating a new instance are referred to as
    ``init``-functions.

This transaction may also include some amount of GTU, which is added to
the balance of the smart contract and is accessible in the ``init``-function.
If the ``init``-function is successful, it returns the initial state of the
instance.

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
