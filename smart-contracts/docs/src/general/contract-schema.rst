.. _contract-schema:

===================================
Smart contract schema
===================================

On the blockchain: data, such as the state of an instance and parameters passed
to ``init`` and ``receive``-functions, are represented as a sequence of bytes.

After compilation the smart contract functions still know how to interpret these
bytes, but this information is part of the contract functions and not easy
accessible.

Since reading and writing bytes directly is error prone and impractical for a
user, this information is useful for off-chain tools, wanting to display a smart
contract instance state in a more readable format, or to allow the user to write
contract function parameters in a more friendly format such as JSON.

This information can be capture in a *Smart contract schema*, which can be
embedded into the smart contract module and deployed to the chain, or be
written to a file and passed around off-chain.

Whether to embed or write to file
=====================================

Whether a contract schema should be embedded or written to a file, have it pros
and cons and ultimately it will depend on your situation.

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

.. seealso::

    For instructions on how to build the schema for a
    smart contract in Rust, see :ref:`build-schema`.

Embedding schemas on chain
==========================

.. todo::

    Write the schema is embedded on chain


