.. _Rust: https://www.rust-lang.org/
.. _Cargo: https://doc.rust-lang.org/cargo/

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
   debug information.

Removing host information from build
====================================

The compiled Wasm module contains information from the host machine building the
binary; information such as the absolute path of ``.cargo``.

For most people this is not sensitive information, but it is important to be
aware of.

The paths can be inspected by running:

.. code-block:: console

   strings contract.wasm | grep /home/

.. rubric:: The solution

The ideal solution would be to remove this path entirely, but that is
unfortunately not a trivial task for the general case.

The current fix is to use the ``--remap-path-prefix`` flag for the rust compiler
to change the path being embedded.
It can be passed using the ``RUSTFLAGS`` environment variable:

.. code-block:: console

   $RUSTFLAGS="--remap-path-prefix=$HOME=" cargo concordium build

Which will replace the users home path with the empty string.

The flags can also be set permanently in the ``.cargo/config`` file in your
crate, under the build section:

.. code-block:: toml

   [build]
   rustflags = ["--remap-path-prefix=/home/<user>="]

where `<user>` should be replaced with the user building the wasm module.

.. seealso::

   If the above did not fix it, it might be because of an issue when
   ``rust-src`` is used: https://github.com/rust-lang/rust/issues/73167
