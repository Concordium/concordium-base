.. _schema-json:

==========================
Schema JSON representation
==========================

This is a reference of how bytes, such as the contract state and parameters can
be represented as JSON together with a ``SchemaType``.

.. seealso::

   See :ref:`contract-schema` for more information on this topic.


JSON for schema type
====================

.. code-block:: rust

   enum Type {
       Unit,
       Bool,
       U8,
       U16,
       U32,
       U64,
       I8,
       I16,
       I32,
       I64,
       Amount,
       AccountAddress,
       ContractAddress,
       Timestamp,
       Duration,
       Pair(Type, Type),
       List(SizeLength, Type),
       Set(SizeLength, Type),
       Map(SizeLength, Type>, Type),
       Array(u32, Type),
       Struct(Fields),
       Enum(List (String, Fields)),
   }

``Unit``
--------

No bytes are produced no matter the value given here, example:

``U8``, ``U16``, ``U32``, ``U64``, ``I8``, ``I16``, ``I32``, ``I64``
--------------------------------------------------------------------

Give a JSON number within the size of the schema type.

``Amount``
----------

Supplied as a JSON string in micro GTU. Example of 42 GTU:

.. code-block:: json

   "42000000"

``AccountAddress``
------------------

Supplied as a JSON string. Example:

.. code-block:: json

   "2wkBET2rRgE8pahuaczxKbmv7ciehqsne57F9gtzf1PVdr2VP3"

``ContractAddress``
-------------------

Supplied as a JSON object with ``index`` field and
optionally ``subindex`` field, both JSON numbers. Example:

.. code-block:: json

   { "index": 10, "subindex": 10 }

``Timestamp``
------------------

Supplied as a JSON string using the RFC3339_ format with the precision of
milliseconds. Example:

.. code-block:: json

   "2020-12-11T11:38:37Z"

.. _RFC3339: https://tools.ietf.org/html/rfc3339

``Duration``
------------------

Supplied as a JSON string as a list of time measures separated by whitespace.
A measure is a number followed by the unit and no whitespace between is allowed.
Every measure is accumulated into the total duration. The string is allowed to
contain any number of measures with the same unit in no particular order.

The supported units are:
 - ``ms`` for milliseconds
 - ``s`` for seconds
 - ``m`` for minutes
 - ``h`` for hours
 - ``d`` for days

Example of 10 days, 2 hours and 42 seconds:

.. code-block:: json

   "10d 1h 42s 1h"

``Pair``
--------

Supplied as a JSON array with two items, depending on the
nested types. Example of ``Pair(U8, ContractAddress)``:

.. code-block:: json

   [200, { "index": 0, "subindex": 0}]

``List``
--------

Supplied as a JSON array with items, depending on the
nested type. Example of ``List(U16)``:

.. code-block:: json

   [0, 1, 1, 2, 3, 5, 8, 13, 21, 34]

``Set``
-------

Supplied as a JSON array with *unique* items, depending on the
nested type.
Example of ``List(U16)``:

.. code-block:: json

   [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]

``Map``
-------

Supplied as a JSON array with key-value pairs, depending on the type of
the key and the type of value. Example of ``Map(AccountAddress, U64)``:

.. code-block:: json

   [
     ["2wkBET2rRgE8pahuaczxKbmv7ciehqsne57F9gtzf1PVdr2VP3", 0],
     ["2xBimKCq2tcciegw9NsFXgScCQAsK7vhqKQ2yJPyJ5vPsWLGi5", 15000000]
     ["2xdGJBNoe716cifxi8jYjm7JHBd5vPyd2ZgpnutwwATJ5vDsiw", 12400]
   ]

``Array``
---------

Supplied as a JSON array with the length specified in the
schema and items depending on the nested type. Example of ``Array(12, U8)``:

.. code-block:: json

   [3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5, 9]


``Struct``
----------

Supplied as the fields directly, see below.

``Enum``
--------

An enum variant is supplied as an JSON object containing a single
property, where the name of the variant as the property and the fields as the
value. More about the fields below.

Example of JSON for an enum ``Option``:

.. code-block:: rust

   enum Option {
       None,
       Some(U32)
   }

In JSON the variant ``Some(9)`` is then

.. code-block:: json

   { "Some": [9] }

JSON for schema type fields
===========================

Structs and the different variants in an enum can have fields, and such fields
can either be named or unnamed. Unnamed fields are referenced by position.

.. code-block:: rust

   enum Fields {
       Named(List (String, Type)),
       Unnamed(List Type),
       Empty,
   }

``Named``
---------

Supplied as a JSON object, with the field names as properties and corresponding
values as property values.
The ordering of the fields in JSON is rearranged according to the order in the
schema field type.

Example of named fields in the Rust struct:

.. code-block:: rust

   struct Person {
       id: u32,
       age: u8
   }

In JSON a ``Person`` with an id of 500 and age 35 is written as:

.. code-block:: json

   {
       "id": 500,
       "age": 35
   }


``Unnamed``
-----------

Supplied as a JSON array, with the fields as items corresponding to the types in
the field schema.

Example of unnamed fields in the Rust struct:

.. code-block:: rust

   struct Person(u32, u8)

In JSON a ``Person`` with an id of 500 and age 35 is written as:

.. code-block:: json

   [500, 35]

``Empty``
---------

Supplied as an empty JSON array.

Example of empty fields in the Rust enum ``Option``:

.. code-block:: rust

   enum Option {
       None,
       Some(U32)
   }

In JSON a ``None`` variant is written as:

.. code-block:: json

   { "None": [] }
