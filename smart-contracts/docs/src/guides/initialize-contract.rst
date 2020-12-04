.. _initialize-contract:

====================================
Initialize a smart contract instance
====================================

This guide will show you how to initialize a smart contract from a deployed
smart contract module with parameters in JSON or binary format.
Additionally, it will show how to name an instance.

Preparation
===========

Make sure to have the latest ``concordium-client`` installed and a smart
contract deployed in some module on-chain.

.. seealso::

   For instructions on how to install ``concordium-client`` see
   :ref:`setup-tools`.

   For instructions on how to deploy a smart contract module see :ref:`deploy-module`.

Since initializing a smart contract is a transaction, you should also make sure
to have ``concordium-client`` setup with an account with enough GTU to pay for
the transaction.

.. note::

   The cost of this transaction depends on the size of the parameters sent to
   the ``init``-function and the complexity of the function itself.

Initialization
==============

To initialize an instance of the parameterless smart contract ``my_contract``
from a deployed module with reference
``9eb82a01d96453dbf793acebca0ce25c617f6176bf7a564846240c9a68b15fd2``, run the
following command:

.. code-block:: console

   $concordium-client contract init \
            9eb82a01d96453dbf793acebca0ce25c617f6176bf7a564846240c9a68b15fd2 \
            --contract my_contract

.. note::

   Using module references directly can be inconvenient so :ref:`adding local names
   to them is recommended <naming-a-module>`.

.. _init-passing-parameter-json:

Passing parameters using JSON
-----------------------------

A JSON parameter can be passed if a :ref:`smart contract schema
<contract-schema>` is supplied, either as a file or embedded in the module.

.. seealso::

   :ref:`Read more about why and how to use smart contract schemas <contract-schema>`.

To initialize an instance of the contract ``my_parameter_contract`` from the
module with reference
``9eb82a01d96453dbf793acebca0ce25c617f6176bf7a564846240c9a68b15fd2`` with the
JSON parameter file ``my_parameter.json``, run the following command:

.. code-block:: console

   $concordium-client contract init \
            9eb82a01d96453dbf793acebca0ce25c617f6176bf7a564846240c9a68b15fd2 \
            --contract my_parameter_contract \
            --parameter-json my_parameter.json

.. note::

   If a given module does not contain an embedded schema, it can be supplied
   using the ``--schema /path/to/schema.bin`` parameter.

.. note::

   GTU can also be transferred to a contract during initialization using the
   ``--amount AMOUNT`` parameter.


.. _init-passing-parameter-bin:

Passing parameters using binary
-------------------------------

When passing a binary parameter, a :ref:`contract schema <contract-schema>` is
not needed.

To initialize an instance of the contract ``my_parameter_contract`` from the
module with reference
``9eb82a01d96453dbf793acebca0ce25c617f6176bf7a564846240c9a68b15fd2`` with the
binary parameter file ``my_parameter.bin``, run the following command:

.. code-block:: console

   $concordium-client contract init \
            9eb82a01d96453dbf793acebca0ce25c617f6176bf7a564846240c9a68b15fd2 \
            --contract my_parameter_contract \
            --parameter-bin my_parameter.bin

.. note::

   The parameter passed can be accessed through `parameter_cursor()`_ and
   subsequently deserialized automatically using `get()`_ or manually using
   `read()`_ (or a similar function from the same Trait).

.. _naming-an-instance:

Naming a contract instance
==========================

Optionally, a contract instance can be named, which makes referencing them
easier.
The name is only stored locally by ``concordium-client``, and is not visible
on-chain.

.. seealso::
   For an explanation of how and where the names and other local settings are
   stored, see :ref:`local-settings`.

To add a name during initialization, the ``--name`` parameter is used.

Here, we are initializing the contract ``my_contract`` from the deployed module
``9eb82a01d96453dbf793acebca0ce25c617f6176bf7a564846240c9a68b15fd2`` and naming
it ``my_named_contract``:

.. code-block:: console

   $concordium-client contract init \
            9eb82a01d96453dbf793acebca0ce25c617f6176bf7a564846240c9a68b15fd2 \
            --contract my_contract \
            --name my_named_contract

A name can also be added to contract instances that have already been
initialized by yourself or, even, by someone else.
To name the contract with address ``0`` as ``my_named_contract``, run the
following command:

.. code-block:: console

   $concordium-client contract name 0 --name my_named_contract

.. _parameter_cursor():
   https://docs.rs/concordium-std/0.2.0/concordium_std/trait.HasInitContext.html#tymethod.parameter_cursor
.. _get(): https://docs.rs/concordium-std/0.2.0/concordium_std/trait.Get.html#tymethod.get
.. _read(): https://docs.rs/concordium-std/0.2.0/concordium_std/trait.Read.html#method.read_u8
