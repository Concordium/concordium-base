.. _initialize-contract:

====================================
Initialize a smart contract instance
====================================

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

To create an instance of a smart contract from a deployed module, we need a
reference to the deployed module.

.. code-block:: sh

    concordium-client contract init <module-reference-or-name> \
                                    --contract <name-of-contract>

.. _init-passing-parameters:

Passing parameter
-----------------

To pass a parameter to the ``init``-function we can use ``--parameter-bin
<binary-file>`` or if a contract schema is present, either embedded in the
module or provided with ``--schema <schema-file>``, we can use
``--parameter-json <json-file>``.

.. seealso::

    For a reference on how the schema is used with JSON see :ref:`schema-json`.
