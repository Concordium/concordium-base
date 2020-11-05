.. _deploy_module:

==============================
Deploy a smart contract module
==============================

This guide will show you how to deploy a smart contract module *on chain*.

Preparation
=============

Make sure to have the latest ``concordium-client`` installed and a smart
contract module ready to be deployed.

.. seealso::
    For instructions on how to install ``concordium-client`` see
    :ref:`setup_tools`.

Since deploying a smart contract module is done in the form of a transaction,
you will also need to have ``concordium-client`` setup with an account with
enough GTU to pay for the transaction.

.. note::
    The cost of the transaction will depend on the size of the smart contract
    module.

.. todo::
    If there is a way, to calculate estimate the cost, explain here or put link
    to it.

Deployment
============

To deploy a smart contract module ``crowdfunding.wasm`` run the following
command:

.. code-block:: sh

    concordium-client module deploy crowdfunding.wasm

If successful, the module reference is printed, which is used to create
instances.

.. seealso::

    For a guide on how to initialize smart contracts from a deployed module see
    :ref:`initialize_contract`.

Optionally a name can be specified to easier referencing of the module. The name
is only stored locally by ``concordium-client``, and is not visible on chain.

.. code-block:: sh

    concordium-client module deploy crowdfunding.wasm --name Crowdfunding
