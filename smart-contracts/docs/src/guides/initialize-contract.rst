.. _initialize-contract:

======================================
Initializing a smart contract instance
======================================

This guide will show you how to initialize a smart contract from a deployed
smart contract module.

Preparation
=============

Make sure to have the latest ``concordium-client`` installed and a smart
contract deployed in some module on chain.

.. seealso::
    For instructions on how to install ``concordium-client`` see
    :ref:`setup-tools`.

    For how to deploy a smart contract module see :ref:`deploy-module`.

Since initializing a smart contract is a transaction, you should also make sure
to have ``concordium-client`` setup with an account with enough GTU to pay for
the transaction.

.. note::
    The cost of this transaction depends on the size of the parameters send to
    the ``init``-function.

Initializing
============

To initialize an instance of a smart contract from a deployed module, run the
following command:

.. code-block:: sh

    concordium-client contract init <module-tbd> --energy <max-energy> [--func <init-name>] [--params <binary-file>] [--path] [--name <name>]

