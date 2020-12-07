.. _inspect-instance:

=================================
Inspect a smart contract instance
=================================

This guide will show you how to inspect a smart contract instance.
Inspecting an instance will show you its name, owner, module reference, balance,
state and receive-functions:

Preparation
===========

Make sure to have the latest ``concordium-client`` installed and a smart
contract instance on-chain to inspect.

.. seealso::
    For instructions on how to install ``concordium-client`` see
    :ref:`setup-tools`.

    For how to deploy a smart contract module see :ref:`deploy-module` and for
    how to create an instance :ref:`initialize-contract`

Inspection
==========

To inspect, or show, information about a smart contract instance with the
address index ``0``, run the following command:

.. code-block:: console

   $concordium-client show 0

The output should be similar to the following:

.. code-block:: console

   Contract:        my_contract
   Owner:           '4Lh8CPhbL2XEn55RMjKii2XCXngdAC7wRLL2CNjq33EG9TiWxj' (default)
   ModuleReference: 'd121f262f3d34b9737faa5ded2135cf0b994c9c32fe90d7f11fae7cd31441e86'
   Balance:         0.000000 GTU
   State:
       {
           "first_field": 0,
           "second_field": 42
       }
   Methods:
    - receive_one
    - receive_two

.. seealso::

   For more information about indexes and subindexes for instance addresses
   see :ref:`references-and-addresses`.

The level of detail of an inspection depends on whether the ``show`` command has
access to a :ref:`contract schema <contract-schema>`.
If the schema is embedded, it will be used implicitly.
Otherwise, a schema can be provided using ``--schema /path/to/schema.bin``
parameter.

.. note::

   A schema file provided using the ``--schema`` parameter will take precedence
   over an embedded schema.

.. seealso::

   :ref:`Read more about why and how to use smart contract schemas <contract-schema>`.
