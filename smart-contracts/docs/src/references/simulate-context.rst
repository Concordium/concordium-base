.. _simulate-context:

===================
Simulation contexts
===================

This is a reference of how the init- and receive-context is specified as JSON,
when :ref:`simulating contract functions locally<local-simulate>`.

Init context
============

The context accessible in an ``init``-function.

Example of context

.. code-block:: json

    {
        "metadata": {
            "slotNumber": 1,
            "blockHeight": 1,
            "finalizedHeight": 1,
            "slotTime": 0
        },
        "initOrigin": "3uxeCZwa3SxbksPWHwXWxCsaPucZdzNaXsRbkztqUUYRo1MnvF"
    }

``metadata``
------------

JSON Object containing the chain meta data, see :ref:`context-metadata` for a
reference of the fields.

``initOrigin``
--------------

The account address which triggered the invocation of the ``init``-function, by
instantiating the smart contract.

Example:

.. code-block:: json

   "3uxeCZwa3SxbksPWHwXWxCsaPucZdzNaXsRbkztqUUYRo1MnvF"


Receive context
===============

The context accessible in a ``receive``-function.

Example of context:

.. code-block:: json

    {
        "metadata": {
            "slotNumber": 1,
            "blockHeight": 1,
            "finalizedHeight": 1,
            "slotTime": 0
        },
        "invoker": "3uxeCZwa3SxbksPWHwXWxCsaPucZdzNaXsRbkztqUUYRo1MnvF",
        "selfAddress": {"index": 0, "subindex": 0},
        "selfBalance": "0",
        "sender": {
            "type": "account",
            "address": "3uxeCZwa3SxbksPWHwXWxCsaPucZdzNaXsRbkztqUUYRo1MnvF"
        },
        "owner": "3uxeCZwa3SxbksPWHwXWxCsaPucZdzNaXsRbkztqUUYRo1MnvF"
    }

``metadata``
------------

JSON Object containing the chain meta data, see :ref:`context-metadata` for a
reference of the fields.

``invoker``
-----------

The account address which made the transaction triggering the invocation of the
``receive``-function, by updating a smart contract instance.

Example:

.. code-block:: json

   "3uxeCZwa3SxbksPWHwXWxCsaPucZdzNaXsRbkztqUUYRo1MnvF"

``sender``
----------

The address of the sender of the message triggering the ``receive``-function.
Can be either a smart contract instance or an account address, given as a JSON
object.

Example of account address:

.. code-block:: json

   { "type": "account", "address": "3uxeCZwa3SxbksPWHwXWxCsaPucZdzNaXsRbkztqUUYRo1MnvF" }

Example of contract address:

.. code-block:: json

   { "type": "contract", "address": { "index": 0, "subindex": 0 } }

``owner``
---------

JSON string containing the account address of the owner of the smart contract
instance.

Example:

.. code-block:: json

   "3uxeCZwa3SxbksPWHwXWxCsaPucZdzNaXsRbkztqUUYRo1MnvF"

``selfAddress``
---------------

JSON object describing the contract address of the current smart contract
instance.
Must contain the ``index`` and ``subindex`` fields with JSON numbers.

Example:

.. code-block:: json

   { "index": 0, "subindex": 0 }

``selfBalance``
---------------

A JSON string with the balance of the smart contract instance in micro GTU.

Example:

.. code-block:: json

   "100"

.. _context-metadata:

Chain meta data
===============

Both the init- and receive-context contains a ``metadata`` section containing
information of the current status of the blockchain, according to the node
running the smart contract.

Example:

.. code-block:: json

   {
         "slotNumber": 123456789,
         "blockHeight": 123456789,
         "finalizedHeight": 123456789,
         "slotTime": 123456789
   }


``slotNumber``
--------------

The current slot number for the current block as a JSON number.

``slotTime``
------------

The slot time at the beginning of the current block as a JSON number.

``blockHeight``
---------------

The block height of the current block as a JSON number.


``finalizedHeight``
-------------------

The block height of the last finalized block as a JSON number.
