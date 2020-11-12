.. _build-schema:

==========================
Build a contract schema
==========================

The guide will show you how to build a smart contract schema, how to export it
to a file and/or embed the schema into the smart contract module, all using
``cargo-concordium``.

Preparation
=====================
First ensure you have ``cargo-concordium`` installed and if not the guide
:ref:`setup-tools` will help you.

We also need the rust source code of the smart contract you wish to build
a schema for.

Setup the contract for a schema
=================================
In order to build the contract schema, we first have to prepare our smart
contract for building the schema.

First step is to add a ``build-schema`` feature to the ``Cargo.toml``::

    ...
    [features]
    build-schema = []
    ...

Now we can choose which parts of our smart contract to included in the schema.
The options are to include a schema for the contract state, and/or for each of
the parameters of ``init``-functions and ``receive``-functions.

Every type we want to include in the schema must implement the ``SchemaType``
trait.
For most cases this can be done, using ``#[derive(SchemaType)]``::

    #[derive(SchemaType)]
    struct SomeType {
        ...
    }

.. todo::
    Link documentation for SchemaType

Including contract state
-------------------------
To generate and include the schema for the contract state we annotate the type
with the ``#[contract-state]`` macro::

    #[contract-state]
    #[derive(SchemaType)]
    struct MyState {
        ...
    }

Including function parameters
-------------------------------
To generate and include the schema for parameters for ``init`` and
``receive``-functions, we set the optional ``parameter`` attribute for the
``#[init(..)]`` and ``#[receive(..)]`` macro::

    #[derive(SchemaType)]
    enum InitParameter { ... }

    #[derive(SchemaType)]
    enum ReceiveParameter { ... }

    #[init(contract = "my_contract", parameter = "InitParameter")]
    fn contract_init<...> (...){ ... }

    #[receive(contract = "my_contract", name = "my_receive", parameter = "ReceiveParameter")]
    fn contract_receive<...> (...){ ... }



Building the schema
===============================
Now we are ready to build the actual schema using ``cargo-concordium``, and we
have the options to embed the schema and/or write the schema to a file.

.. todo::
    Link to more details of why to choose either

Embedding the schema
-------------------------
In order to embed the schema into the smart contract module, we add
``--schema-embed`` to the build command::

    cargo concordium build --schema-embed

If successful the output of the command will tell you the total size of the
schema in bytes.

Outputting a schema file
-------------------------
To output the schema into a file, we can use the ``--schema-output=<file>``
where ``<file>`` is a path of the file to create::

    cargo concordium build --schema-output="/some/path/schema.bin"
