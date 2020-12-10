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

   The cost of this transaction depends on the size of the parameters sent to
   the ``receive``-function and the complexity of the function itself.

Interaction
===========

To update an instance with address index ``0`` using the parameterless
``receive``-function ``my_receive`` while allowing up to 1000 energy to be used,
run the following command:

.. code-block:: console

   $concordium-client contract update 0 --func my_receive --energy 1000

If successful, the output should be similar to the following:

.. code-block:: console

   Successfully updated contract instance {"index":0,"subindex":0} using the function 'my_receive'.

Passing parameters in JSON format
---------------------------------

A parameter in JSON format can be passed if a :ref:`smart contract schema
<contract-schema>` is supplied, either as a file or embedded in the module.
The schema is used to serialize the JSON into binary.

.. seealso::

   :ref:`Read more about why and how to use smart contract schemas
   <contract-schema>`.

To update an instance with address index ``0`` using the ``receive``-function
``my_parameter_receive`` with a parameter file ``my_parameter.json`` in JSON
format, run the following command:

.. code-block:: console

   $concordium-client contract update 0 --func my_parameter_receive \
            --energy 1000 \
            --parameter-json my_parameter.json

If successful, the output should be similar to the following:

.. code-block:: console

   Successfully updated contract instance {"index":0,"subindex":0} using the function 'my_parameter_receive'.

Otherwise, an error describing the problem is displayed.
Common errors are described in the next section.

.. seealso::

   For more information about contract instance addresses, see
   :ref:`references-on-chain`.

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

  * If the update requires more energy than the maximum specified with
    the ``--energy`` parameter, the transaction will fail with the following
    message:

    .. code-block:: console

       Error: Transaction failed before it got committed. Most likely because it
       was invalid.

.. note::

   If a given module does not contain an embedded schema, it can be supplied
   using the ``--schema /path/to/schema.bin`` parameter.

.. note::

   GTU can also be transferred to a contract during updates using the
   ``--amount AMOUNT`` parameter.

Passing parameters in binary format
-----------------------------------

When passing parameters in binary format, a
:ref:`contract schema <contract-schema>` is not needed.

To update an instance with address index ``0`` using the ``receive``-function
``my_parameter_receive`` with a parameter file ``my_parameter.bin`` in binary
format, run the following command:

.. code-block:: console

   $concordium-client contract update 0 --func my_parameter_receive \
            --energy 1000 \
            --parameter-bin my_parameter.bin

If successful, the output should be similar to the following:

.. code-block:: console

   Successfully updated contract instance {"index":0,"subindex":0} using the function 'my_parameter_receive'.

.. seealso::

   For information on how to work with parameters in smart contracts, see
   :ref:`working-with-parameters`.

.. _parameter_cursor():
   https://docs.rs/concordium-std/latest/concordium_std/trait.HasInitContext.html#tymethod.parameter_cursor
.. _get(): https://docs.rs/concordium-std/latest/concordium_std/trait.Get.html#tymethod.get
.. _read(): https://docs.rs/concordium-std/latest/concordium_std/trait.Read.html#method.read_u8
