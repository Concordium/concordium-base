===================================
Smart Contracts on the chain
===================================

In this section we describe all aspects of Smart Contracts that are relevant
for a node in the network.

Life-cycle
===================================

The following operations are possible for Smart Contracts.

- Deploy a Smart Contract.
- Initialize a Smart Contract instance from a deployed smart contract.
- Invoke an existing Smart Contract instance with a specific message.
  This can be done repeatedly and can both update the state and the GTU amount
  on the Smart Contract instance, as well as send messages to other smart
  contract instances.

All of these actions are done as transactions that are sent by accounts,
recorded in blocks, and paid for by the sender of the transaction.


Format of Smart Contracts
===================================

A smart contract is deployed onto the chain as a single WebAssembly module, as
part of a single transaction.

.. note::
    This means the cost of deploying a Smart Contract is affected by the size of
    the WebAssembly module.

.. note::
    This also means the Smart Contract module is currently limited to the
    maximum size of a single transaction.

The module must be self-contained, and only have a restricted list of imports
that interact with the chain.
These are provided by the host environment and are available in the Smart
Contract by importing a module named ``concordium``.

.. todo::
    Link to ``concordium`` module description

The module can then export functions for creating smart contract instances.
To call such a function and instantiate a smart contract, one sends a special
transaction with the information of where to find the smart contract on chain
and which function from the module to use for creating an instance.

.. note::
    The functions for creating a new instance, are referred to as
    ``init``-functions.

This transaction may also include some amount of GTU, which is added to
the balance of the smart contract and is accessible in the ``init``-function.
If the ``init``-function is successful, it returns the initial state of the
instance.

.. todo::
    Write about smart contract's ``receive``-functions.
