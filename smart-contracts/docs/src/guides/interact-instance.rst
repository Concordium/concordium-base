.. _interact-instance:

==========================================
Interact with a smart contract instance
==========================================

This guide will show you, how to interact with a smart contract instance, which
means triggering a ``receive``-function, possibly update the state of the
instance.

Preparation
=============

Make sure to have the latest ``concordium-client`` installed and a smart
contract instance on chain to interact with.

.. seealso::
    For instructions on how to install ``concordium-client`` see
    :ref:`setup-tools`.
    For how to deploy a smart contract module see :ref:`deploy-module` and for
    how to create an instance :ref:`initialize-contract`

Interacting with a smart contract instance is done in the form of a transaction,
so will also need to have ``concordium-client`` setup with an account with
enough GTU to pay for the transaction.

.. note::
    The cost of this transaction depends on the size of the parameters send to
    the ``receive``-function.

Interaction
===========

To interact with a smart contract instance, run the following command

.. code-block:: sh

    concordium-client contract update <index-or-name> --energy <max-energy> [--func <receive-name>] [--params <binary-file>] [--subindex <address-subindex>]

- <index-or-name> can be either an index or a contract name.
- Similar to init, it takes an optional --func flag, which defaults to
  "receive".
- Parameters work in the same way as with init.
