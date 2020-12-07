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
``9eb82a01d96453dbf793acebca0ce25c617f6176bf7a564846240c9a68b15fd2`` while
allowing up to 1000 energy to be used, run the
following command:

.. code-block:: console

   $concordium-client contract init \
            9eb82a01d96453dbf793acebca0ce25c617f6176bf7a564846240c9a68b15fd2 \
            --contract my_contract \
            --energy 1000

If successful, the output should be similar to the following:

.. code-block:: console

   Contract successfully initialized with address: {"index":0,"subindex":0}

Seeing this message means that a new on-chain contract instance has been created
with the address shown.

.. note::

   Using module references directly can be inconvenient so :ref:`adding local names
   to them is recommended <naming-a-module>`.

.. _init-passing-parameter-json:

Passing parameters in JSON format
---------------------------------

A parameter in JSON format can be passed if a :ref:`smart contract schema
<contract-schema>` is supplied, either as a file or embedded in the module.
The schema is used to serialize the JSON into binary.

.. seealso::

   :ref:`Read more about why and how to use smart contract schemas <contract-schema>`.

   :ref:`Parameters can also passed in binary format <init-passing-parameter-bin>`.

To initialize an instance of the contract ``my_parameter_contract`` from the
module with reference
``9eb82a01d96453dbf793acebca0ce25c617f6176bf7a564846240c9a68b15fd2`` with a
parameter file ``my_parameter.json`` in JSON format, run the following command:

.. code-block:: console

   $concordium-client contract init \
            9eb82a01d96453dbf793acebca0ce25c617f6176bf7a564846240c9a68b15fd2 \
            --contract my_parameter_contract \
            --energy 1000 \
            --parameter-json my_parameter.json

If successful, the output should be similar to the following:

.. code-block:: console

   Contract successfully initialized with address: {"index":0,"subindex":0}

Otherwise, an error describing the problem is displayed.

Common Errors
^^^^^^^^^^^^^

* Parameter of incorrect type:

  * If the parameter provided in JSON format does not conform to the type
    specified in the schema, an error message will be displayed. For example:

    .. code-block:: console

       Error: Could not decode parameters from file 'my_parameter.json' as JSON:
       Expected value of type "UInt64", but got: "hello".
       In field 'first_field'.
       In {
           "first_field": "hello",
           "second_field": 42
       }.

* Insufficient energy allowed:

  * If the initialization requires more energy than the maximum specified with
    the ``--energy`` parameter, the transaction will fail with the following
    message:

    .. code-block:: console

       Error: Transaction failed before it got committed. Most likely because it
       was invalid.

.. note::

   If a given module does not contain an embedded schema, it can be supplied
   using the ``--schema /path/to/schema.bin`` parameter.

.. note::

   GTU can also be transferred to a contract instance during initialization
   using the ``--amount AMOUNT`` parameter.


.. _init-passing-parameter-bin:

Passing parameters in binary format
-----------------------------------

When passing parameters in binary format, a :ref:`contract schema
<contract-schema>` is not needed.

To initialize an instance of the contract ``my_parameter_contract`` from the
module with reference
``9eb82a01d96453dbf793acebca0ce25c617f6176bf7a564846240c9a68b15fd2`` with the
parameter file ``my_parameter.bin`` in binary format, run the following command:

.. code-block:: console

   $concordium-client contract init \
            9eb82a01d96453dbf793acebca0ce25c617f6176bf7a564846240c9a68b15fd2 \
            --contract my_parameter_contract \
            --energy 1000 \
            --parameter-bin my_parameter.bin


If successful, the output should be similar to the following:

.. code-block:: console

   Contract successfully initialized with address: {"index":0,"subindex":0}

.. note::

   The parameter passed can be accessed through `parameter_cursor()`_ and
   subsequently deserialized automatically using `get()`_ or manually using
   `read()`_ (or a similar function from the same trait).

.. _naming-an-instance:

Naming a contract instance
==========================

A contract instance can be given a local alias, or *name*, which makes
referencing it easier.
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
            --energy 1000 \
            --name my_named_contract


If successful, the output should be similar to the following:

.. code-block:: console

   Contract successfully initialized with address: {"index":0,"subindex":0} (my_named_contract).

Contract instances can also be named using the ``name`` command.
To name an instance with the address index ``0`` as ``my_named_contract``, run
the following command:

.. code-block:: console

   $concordium-client contract name 0 --name my_named_contract

If successful, the output should be similar to the following:

.. code-block:: console

   Contract address {"index":0,"subindex":0} was successfully named 'my_named_contract'.

.. seealso::

   For more information about indexes and subindexes for instance addresses
   see :ref:`references-and-addresses`.

.. _parameter_cursor():
   https://docs.rs/concordium-std/0.2.0/concordium_std/trait.HasInitContext.html#tymethod.parameter_cursor
.. _get(): https://docs.rs/concordium-std/0.2.0/concordium_std/trait.Get.html#tymethod.get
.. _read(): https://docs.rs/concordium-std/0.2.0/concordium_std/trait.Read.html#method.read_u8
