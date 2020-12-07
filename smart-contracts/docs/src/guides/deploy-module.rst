.. _deploy-module:

==============================
Deploy a smart contract module
==============================

This guide will show you how to deploy a smart contract module *on-chain* and
how to name it.

Preparation
===========

Make sure to have the latest ``concordium-client`` installed and a smart
contract module ready to be deployed.

.. seealso::
   For instructions on how to install ``concordium-client`` see
   :ref:`setup-tools`.

Since deploying a smart contract module is done in the form of a transaction,
you will also need to have ``concordium-client`` setup with an account with
enough GTU to pay for the transaction.

.. note::
   The cost of the transaction is dependent on the size of the smart contract
   module. ``concordium-client`` shows the cost and asks for confirmation
   before it executes any transaction.

Deployment
==========

To deploy a smart contract module ``my_module.wasm``, run the following
command:

.. code-block:: console

   $concordium-client module deploy my_module.wasm

If successful, the output should be similar to the following:

.. code-block:: console

   Module successfully deployed with reference: 'd121f262f3d34b9737faa5ded2135cf0b994c9c32fe90d7f11fae7cd31441e86'.

Make note of the module reference as it is used when creating smart contract
instances.

.. seealso::

   For a guide on how to initialize smart contracts from a deployed module see
   :ref:`initialize-contract`.

.. _naming-a-module:

Naming a module
===============

A module can be given a local alias, or *name*, which makes referencing it
easier.
The name is only stored locally by ``concordium-client``, and is not
visible on-chain.

.. seealso::
   For an explanation of how and where the names and other local settings are
   stored, see :ref:`local-settings`.

To add a name during deployment, the ``--name`` parameter is used.
Here, we are naming the module ``my_deployed_module``:

.. code-block:: console

   $concordium-client module deploy my_module.wasm --name my_deployed_module

If successful, the output should be similar to the following:

.. code-block:: console

   Module successfully deployed with reference: '9eb82a01d96453dbf793acebca0ce25c617f6176bf7a564846240c9a68b15fd2' (my_deployed_module).

Modules can also be named using the ``name`` command.
To name a deployed module with reference
``9eb82a01d96453dbf793acebca0ce25c617f6176bf7a564846240c9a68b15fd2`` as
``some_deployed_module``, run the following command:

.. code-block:: console

   $concordium-client module name \
             9eb82a01d96453dbf793acebca0ce25c617f6176bf7a564846240c9a68b15fd2 \
             --name some_deployed_module

The output should be similar to the following:

.. code-block:: console

   Module reference 9eb82a01d96453dbf793acebca0ce25c617f6176bf7a564846240c9a68b15fd2 was successfully named 'some_deployed_module'.
