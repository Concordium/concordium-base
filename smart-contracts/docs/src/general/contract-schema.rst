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
structured representation, such as JSON.

.. seealso::

    For instructions on how to build the schema for a smart contract module in
    Rust, see :ref:`build-schema`.

Why use a contract schema
=========================

On the blockchain; data, such as the state of an instance and parameters passed
to ``init`` and ``receive``-functions, are represented as sequences of bytes.

Usually these bytes have structure and this structure is known to the smart
contract as part of the contract functions, but outside of these functions it
can be difficult to make sense of the bytes.

When inspecting the state of a smart contract instance with complex state;
bytes are difficult to read and likewise is it difficult to pass complex
parameters to smart contract functions, if they have to be bytes written by
hand.
The solution is to capture this information in a *Smart contract schema*, which
describes how to make structure from the bytes, and can be used by external
tools.

.. note::

    Tools like ``concordium-client`` can use a schema to serialize JSON into bytes
    for when :ref:`specifying a parameter<init-passing-parameters>`, and deserialize the
    state of contract instances to JSON.

The schema is then either embedded into the smart contract module deployed
to the chain, or is written to a file and passed around off-chain.

Should you embed or write to file?
==================================

Whether a contract schema should be embedded or written to a file, depends on
your situation.

Embedding the schema into the smart contract module, distributes the schema
together with the contract ensuring the correct schema is being used and also
allows anyone to use it directly. The downside is that the smart contract module
becomes bigger in size and therefore more expensive to deploy. But unless the
smart contract uses very complex types for the state and parameters, the size of
the schema is likely to be negligible compared to the size of the smart contract
itself.

Having the schema in a separate file, allows you to have the schema without
paying for the extra bytes when deploying.
The downside is that you instead have to distribute the schema file through some
other channel and ensure contract users are using the correct file with your
smart contract.

The schema format
=================

A schema can contain the structure information for a smart contract module
and for each contract it can contain the description of the state and
parameters for ``init`` and each of the ``receive``-functions.
Each of these descriptions are referred to as a *schema type* and are always
optional to include in the schema.

Currently the supported schema types are inspired by what is commonly used in
the Rust programming language:

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
        Empty,
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
reader to the `implementation in Rust`_.

.. _contract-schema-which-to-choose:

Embedding schemas on chain
==========================

Schemas are embedded into smart contract modules using the `custom
section`_ feature of Wasm modules.
This allows Wasm modules to include a named section of bytes, which does not
affect the semantics of running the Wasm module.

All schemas are collected and added in one custom section named
``concordium-schema-v1``. This collection is a list of pairs, containing the
name of the contract encoded in UTF-8 and the contract schema bytes.

.. _`custom section`: https://webassembly.github.io/spec/core/appendix/custom.html
.. _`implementation in Rust`: https://gitlab.com/Concordium/smart-contracts/-/blob/master/concordium-contracts-common/src/schema.rs
