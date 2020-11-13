.. Should answer:
..
.. - Why should I use a schema?
.. - What is a schema?
.. - Where to use a schema?
.. - How is a schema embedded?
.. - Should I embed or write to file?
..

.. _contract-schema:

===================================
Smart contract schema
===================================

A smart contract schema is a description of how to represented bytes in a more
structured representation, it can be used by external tools when displaying the
state of a smart contract instance and for specifying parameters using a
structured representation.

.. seealso::

    For instructions on how to build the schema for a
    smart contract in Rust, see :ref:`build-schema`.

Why use a contract schema
=========================

On the blockchain; data, such as the state of an instance and parameters passed
to ``init`` and ``receive``-functions, are represented as sequences of bytes.

Usually these bytes have structure, and this structure is known to the smart
contract and is part of contract functions, but outside of the functions it can
be difficult to make sense of these bytes.

When inspecting the state of a smart contract instance with a complex state
bytes can be difficult read and likewise is it difficult to pass complex
parameters to smart contract functions by writing bytes by hand.
The solution is to capture this information in a *Smart contract schema*, which
describes how to make structure from the bytes, and can be used by external
tools.

The contract schema is either embedded into the smart contract module deployed
to the chain, or is written to a file and passed around off-chain.

The contract schema format
==========================

Ironically, the contract schema itself is represented as bytes, and *may*
include how to represent the type of the contract state and types for any number
of parameters for contract functions.

Currently the supported schema types are inspired by what is possible in the
Rust programming language:

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
        Pair(Type, Type),
        String(SizeLength),
        List(SizeLength, Type),
        Set(SizeLength, Type),
        Map(SizeLength, Type, Type),
        Array(u32, Type),
        Struct(Fields),
        Enum(List (String, Fields)),
    }

    enum Fields {
        Named(List (String, Type)),
        Unnamed(List Type),
        Unit,
    }


Where ``SizeLength`` describes the number of bytes used to describe the length
of a variable length type, such as ``List``.

.. code-block:: rust

    enum SizeLength {
        U8,
        U16,
        U32,
        U64,
    }

For a reference to how a schema type is serialized into bytes, we refer the
reader to read the implementation.

.. todo::
    Link implementation of schema::Type


Should you embed or write to file?
=====================================

Whether a contract schema should be embedded or written to a file, depends on
your situation.

Embedding the schema into the smart contract module, distributes the schema
together with the contract ensuring the correct schema is being used and also
allows anyone to use it directly.
The downside is that the smart contract module becomes more expensive to deploy,
depending on the size of the schema.

Having the schema in a separate file, allows you to have the schema without
paying for the extra bytes, it might required to embed it.
The downside it that you instead have to distribute the schema file through some
other channel and ensure contract users are using the correct file with your
smart contract.

Embedding schemas on chain
==========================

A contract schema is embedded into a smart contract module using the `custom
section`_ feature of Wasm modules.

This allows Wasm modules to include a named section of bytes, which does not
affect the semantics of running the Wasm module.

For every contract schema to embed into a module, we add as a custom section
named after the smart contract, prefixed with ``concordium-schema-``

.. _`custom section`: https://webassembly.github.io/spec/core/appendix/custom.html
