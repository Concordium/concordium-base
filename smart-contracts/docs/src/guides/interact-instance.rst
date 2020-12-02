.. _interact-instance:

=======================================
Interact with a smart contract instance
=======================================

This guide will show you, how to interact with a smart contract instance, which
means triggering a ``receive``-function, possibly update the state of the
instance.

Preparation
===========

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

To update a contract instance we need the following:

* An address to the instance, which can be acquired by either:

  * Using the address directly,
  * Or, using a :ref:`contract instance name <naming-an-instance>`

* A parameter for the ``receive``-function:

  * This can be in :ref:`JSON <init-passing-parameter-json>` or
    :ref:`binary <init-passing-parameter-bin>` format. For ``receive``-functions
    that do not use a parameter, the command line parameter can be omitted.

To update a contract instance with address ``0`` using the ``receive``-function
``my_receive``, which takes no parameter, use the following command:

.. code-block:: code

    concordium-client contract update 0 --func my_receive

Passing parameter
-----------------

To pass a parameter to the ``receive``-function we can use ``--parameter-bin
BINARY_FILE`` or if a contract schema is present, either embedded in the
module or provided with ``--schema SCHEMA_FILE``, we can use
``--parameter-json JSON_FILE``.

For example, let us update the contract with address ``0`` using the
``my_parameter_receive``-function and the parameter file in JSON format
``parameter.json``. To do so, run the following command:

.. code-block:: console

   concordium-client contract update 0 --func \
                my_parameter_receive --parameter-json parameter.json

.. seealso::

   For a reference on how the schema is used with JSON see :ref:`schema-json`.

   For more information about passing a parameter using ``concordium-client``
   see
   :ref:`the documentation on initializing contracts <init-passing-parameter>`,
   as updating works exactly the same way.
