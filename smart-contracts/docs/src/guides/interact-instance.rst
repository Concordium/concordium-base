.. _interact-instance:

=======================================
Interact with a smart contract instance
=======================================

This guide will show you, how to interact with a smart contract instance, which
means triggering a ``receive``-function that, possibly, updates the state of the
instance.

Preparation
===========

Make sure to have the latest ``concordium-client`` installed and a smart
contract instance on-chain to interact with.

.. seealso::
    For instructions on how to install ``concordium-client`` see
    :ref:`setup-tools`.

    For how to deploy a smart contract module see :ref:`deploy-module` and for
    how to create an instance see :ref:`initialize-contract`.

Since interactions with a smart contract are transactions, you should also make
sure to have ``concordium-client`` setup with an account with enough GTU to pay
for the transactions.

.. note::
    The cost of this transaction depends on the size of the parameters send to
    the ``receive``-function and the complexity of the function itself.

Interaction
===========

To update an instance with address ``0`` using the parameterless
``receive``-function ``my_receive`` run the following command:

.. code-block:: console

    concordium-client contract update 0 --func my_receive

Passing parameters using JSON
-----------------------------

A JSON parameter can be passed if a :ref:`smart contract schema
<contract-schema>` is supplied, either as a file or embedded in the module.

.. seealso::

   :ref:`Read more about why and how to use smart contract schemas
        <contract-schema>`.

To update an instance with address ``0`` using the ``receive``-function
``my_parameter_receive`` with the JSON parameter file ``my_parameter.json``, run
the following command:

.. code-block:: console

   $concordium-client contract update 0 --func my_parameter_receive \
            --parameter-json my_parameter.json

.. note::

   If a given module does not contain an embedded schema, it can be supplied
   using the ``--schema /path/to/schema.bin`` parameter.

.. note::

   GTU can also be transferred to a contract during updates using the
   ``--amount AMOUNT`` parameter.



Passing parameters using binary
-------------------------------

When passing a binary parameter, a :ref:`contract schema <contract-schema>` is
not needed.


To update an instance with address ``0`` using the ``receive``-function
``my_parameter_receive`` with the binary parameter file ``my_parameter.bin``,
run the following command:

.. code-block:: console

   $concordium-client contract update 0 --func my_parameter_receive \
            --parameter-bin my_parameter.bin

.. note::

   The parameter passed can be accessed through `parameter_cursor()`_ and
   subsequently deserialized automatically using `get()`_ or manually using
   `read()`_ (or a similar function from the same Trait).

.. _parameter_cursor():
   https://docs.rs/concordium-std/0.2.0/concordium_std/trait.HasInitContext.html#tymethod.parameter_cursor
.. _get(): https://docs.rs/concordium-std/0.2.0/concordium_std/trait.Get.html#tymethod.get
.. _read(): https://docs.rs/concordium-std/0.2.0/concordium_std/trait.Read.html#method.read_u8
