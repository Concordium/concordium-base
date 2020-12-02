.. _deploy-module:

==============================
Deploy a smart contract module
==============================

This guide will show you how to deploy a smart contract module *on-chain*.

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
    before it executes the transaction.

Deployment
==========

To deploy a smart contract module ``crowdfunding.wasm``, run the following
command:

.. code-block:: console

   $concordium-client module deploy crowdfunding.wasm

If successful, the module reference is printed, which is used to create
instances.

.. seealso::

    For a guide on how to initialize smart contracts from a deployed module see
    :ref:`initialize-contract`.

.. _naming-a-module:

Naming a module
---------------

Optionally, modules can be named, which makes referencing them easier. The name
is only stored locally by ``concordium-client``, and is not visible on-chain.

.. seealso::
   For an explanation of how and where the names and other local settings are
   stored, see :ref:`local-settings`.

To add a name during deployment, the ``--name`` parameter is used. Here, we are
naming the module ``Crowdfunding``:

.. code-block:: console

    $concordium-client module deploy crowdfunding.wasm --name Crowdfunding

A name can also be added to modules that have already been deployed by yourself
or, even, by someone else. To name a module its reference is needed. If you do
not have the reference from when you deployed the module, it can be found using
by listing the modules on-chain:

.. code-block:: console

   $concordium-client module list

The output is similar to the following:

.. code-block:: console

   Modules:
                           Module Reference                           Module Name
   --------------------------------------------------------------------------------
   9eb82a01d96453dbf793acebca0ce25c617f6176bf7a564846240c9a68b15fd2
   d121f262f3d34b9737faa5ded2135cf0b994c9c32fe90d7f11fae7cd31441e86

While it is a bit cumbersome, you can then inspect the modules one at a time
until you find the module you are looking for. For example:

.. code-block:: console

   $concordium-client module inspect \
            d121f262f3d34b9737faa5ded2135cf0b994c9c32fe90d7f11fae7cd31441e86

To name the module ``foo``, run the following command:

.. code-block:: console

   $concordium-client module name \
            d121f262f3d34b9737faa5ded2135cf0b994c9c32fe90d7f11fae7cd31441e86 \
            --name foo
