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
=================

To help building smart contract modules and to take advantage of features
such as :ref:`contract schemas <contract-schema>`, we recommend using the
``cargo-concordium`` tool for building Rust_ smart contracts.

In order to build a smart contract, run:

.. code-block:: console

   $cargo concordium build

This uses Cargo_ for building, but runs further optimizations on the result.

.. seealso::

   For building the schema for a smart contract module, some :ref:`further
   preparation is required <build-schema>`.

.. note::

   It is also possible to compile using Cargo_ directly by running:

   .. code-block:: console

      $cargo build --target=wasm32-unknown-unknown [--release]

   Note that even with ``--release`` set, the produced Wasm module includes
   debug information and, in some cases, embedded local paths.

   .. todo::

      Maybe elaborate or add some link to an explanation.

.. _Rust: https://www.rust-lang.org/
.. _Cargo: https://doc.rust-lang.org/cargo/
