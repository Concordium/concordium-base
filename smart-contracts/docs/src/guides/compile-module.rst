.. _compile-module:

====================================
Compile a Rust smart contract module
====================================

This guide will show you how to compile smart contract module written in Rust to
a Wasm module.

Preparation
===========

Make sure to have Rust and Cargo installed and the ``wasm32-unknown-unknown``
target, together with ``cargo-concordium`` and the Rust source code for a smart
contract module, you wish to compile.

.. seealso::
    For instructions on how to install the developer tools see
    :ref:`setup-tools`.

Compiling to Wasm
====================================

To help building small smart contract modules and to take advantage of features
such as contract schemas, we recommend using the ``cargo-concordium`` tool for
building Rust_ smart contracts.

.. todo::
    Link schemas

In order to build run:

.. code-block:: sh

    cargo concordium build

This uses Cargo_ for building, but runs further optimizations on the result.

.. warning::

    Although it is *not* recommended, it is possible to compile using Cargo_
    directly by running::

        cargo build --target=wasm32-unknown-unknown [--release]

    But even with the ``--release`` set, the produced Wasm module includes debug
    information and in some cases embed paths.

    .. todo::
        Maybe elaborate or add some link to an explanation.

.. _Rust: https://www.rust-lang.org/
.. _Cargo: https://doc.rust-lang.org/cargo/
