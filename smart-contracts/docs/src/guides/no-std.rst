.. _no-std:

======================
Build using ``no_std``
======================

This guide shows how to enable ``no_std`` for your rust smart contract,
potentially reducing the size of the resulting Wasm module by several kilobytes.

Preparation
===========

Compiling ``concordium-std`` without the ``std`` feature requires using the rust
nightly toolchain, which can be installed using ``rustup``:

.. code-block:: console

   $rustup toolchain install nightly

Setting up the module for ``no_std``
====================================

The ``concordium-std`` library exposes a ``std`` feature, which enables the use
of the rust standard library.
This feature is enabled by default.

To disable it, one must simply disable default features for the
``concordium-std`` in the dependencies of your module.

.. code-block:: rust

   [dependencies]
   concordium-std = { version: "=0.2", default-features = false }

To be able to toggle between with and without std, also add a ``std`` to your
own module, which enables the ``std`` feature of ``concordium-std``:

.. code-block:: rust

   [features]
   std = ["concordium-std/std"]

This is the setup of the smart contract examples, where ``std`` for each
smart contract module is enabled by default.

Building the module
===================

In order to use the nightly toolchain, add ``+nightly`` right after
``cargo``:

.. code-block:: console

   $cargo +nightly concordium build

If you want to disable the default features of your own smart contract module,
you can pass extra arguments for ``cargo``:

.. code-block:: console

   $cargo +nightly concordium build -- --no-default-features
