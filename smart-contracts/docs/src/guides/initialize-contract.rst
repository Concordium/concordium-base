.. _initialize-contract:

====================================
Initialize a smart contract instance
====================================

This guide will show you how to initialize a smart contract from a deployed
smart contract module.

Preparation
===========

Make sure to have the latest ``concordium-client`` installed and a smart
contract deployed in some module on chain.

.. seealso::

   For instructions on how to install ``concordium-client`` see
   :ref:`setup-tools`.

   For instructions on how to deploy a smart contract module see :ref:`deploy-module`.

Since initializing a smart contract is a transaction, you should also make sure
to have ``concordium-client`` setup with an account with enough GTU to pay for
the transaction.

.. note::

   The cost of this transaction depends on the size of the parameters send to
   the ``init``-function.

Initialization
==============

To initialize an instance of a smart contract from a deployed module, we need
the following:

* A reference to the module, which can be acquired through one of three ways:

  * By using the module reference directly,
  * By using a :ref:`module name <naming-a-module>`,
  * Or, by providing the path to the module stored locally, while using the
    ``--isPath`` flag.

* A contract name:

  * This is required because a single module can contain multiple smart
    contracts. Each ``init``-function corresponds to a single smart contract.

* A parameter for the ``init``-function:

  * This can be in :ref:`JSON <init-passing-parameter-json>` or
    :ref:`binary <init-passing-parameter-bin>` format. For ``init``-functions that do not
    use a parameter, the command line parameter can be omitted.

Let's assume that we have a deployed module with the name ``my_module`` in which
the contract ``my_contract`` exists. Let's also assume that the ``init``-function
called ``my_contract`` does not need a parameter.

To initialize ``my_contract`` we will then run the following command:

.. code-block:: console

   $concordium-client contract init my_module --contract my_contract

If successful, the address of the instance will be shown.

.. note::

   A smart contract instance can be also :ref:`be named <naming-an-instance>`.

.. _init-passing-parameter:

Passing parameters
------------------

Often, the ``init``-function will take a parameter. This parameter can be supplied
from a file in either :ref:`JSON <init-passing-parameter-json>` or :ref:`binary
<init-passing-parameter-bin>` format.

.. note::

   GTU can also be transferred to a contract during initialization using the
   ``--amount AMOUNT`` parameter.

.. _init-passing-parameter-json:

Using JSON
^^^^^^^^^^

A JSON parameter can be passed if a :ref:`contract-schema` is supplied,
either as a file or embedded in the module.

.. seealso::

   :ref:`Read more about why and how to use smart contract schemas <contract-schema>`.

Let's assume that the module named ``my_module`` contains an embedded schema and a
smart contract called ``my_parameter_contract`` that takes a parameter.

To initialize ``my_parameter_contract`` with the parameter file
``my_parameter.json``, run the following command:

.. code-block:: console

   $concordium-client contract init my_module --contract my_parameter_contract \
                --parameter-json my_parameter.json

.. note::

   If a given module does not contain an embedded schema, it can be supplied
   using the ``--schema SCHEMA`` parameter, where ``SCHEMA`` is the path to a
   schema file.

.. _init-passing-parameter-bin:

Using binary
^^^^^^^^^^^^

When passing a binary parameter, a :ref:`contract schema
<contract-schema>` is not needed.

Following the example in :ref:`init-passing-parameter-json`, let's assume that a
module named ``my_module`` contains a smart contract ``my_parameter_contract``
that takes a parameter.

To initialize ``my_parameter_contract`` with a parameter file
``my_parameter.bin``, run the following command:

.. code-block:: console

   $concordium-client contract init my_module \
                --contract my_parameter_contract \
                --parameter-bin my_parameter.bin

.. note::
   The parameter passed can be accessed through `parameter_cursor() <https://docs.rs/concordium-std/0.2.0/concordium_std/trait.HasInitContext.html#tymethod.parameter_cursor>`_ and
   subsequently deserialized automatically using `get()
   <https://docs.rs/concordium-std/0.2.0/concordium_std/trait.Get.html#tymethod.get>`_
   or manually using
   `read()
   <https://docs.rs/concordium-std/0.2.0/concordium_std/trait.Read.html#method.read_u8>`_
   (or a similar function from the same Trait).

.. _naming-an-instance:

Naming a contract instance
==========================

Optionally, an contract instance can be named, which makes referencing them easier.
The name is only stored locally by ``concordium-client``, and is not visible
on-chain.

.. seealso::
   For an explanation of how and where the names and other local settings are
   stored, see :ref:`local-settings`.

To add a name during initialization, the ``--name`` parameter is used. Here, we
are initializing the contract ``my_contract`` from inside the module
``my_module`` and naming it ``my_named_contract``:

.. code-block:: console

   $concordium-client contract init my_module --contract my_contract \
                --name my_named_contract

A name can also be added to contract instances that have already been
initialized by yourself or, even, by someone else. All that is needed is the
address of the instance:

.. code-block:: console

   $concordium-client contract name CONTRACT_ADDRESS --name NAME

.. seealso::
   :ref:`Modules can also be named <naming-a-module>`
