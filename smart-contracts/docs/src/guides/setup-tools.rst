.. _setup-tools:

=============================
Install tools for development
=============================
Before we can start developing smart contracts, we need to setup the
environment.

Rust and Cargo
==============
First install rustup_, which will install both Rust_ and Cargo_ on your
machine.
Then use ``rustup`` to install the Wasm target, which is used for compilation::

    rustup target add wasm32-unknown-unknown

Cargo Concordium
================

The tool for developing smart contracts for the Concordium blockchain.
It can be used for :ref:`compiling<compile-module>` and
:ref:`testing<unit-test-contract>` smart contracts, and enables features such as
:ref:`building contract schemas<build-schema>`.

.. todo::
    Add links for testing and schemas.

It is installed by running::

    cargo install cargo-concordium

.. note:: Until the tool is released on crates.io_, you instead have to manually
   download it and place it in your PATH.

For a description of how to use the tool run::

    cargo concordium --help

Concordium Client
=================

To deploy smart contract modules and interact with the chain, make sure to have
``concordium-client`` installed on your local system.

.. todo::
    Link to install instructions


.. _Rust: https://www.rust-lang.org/
.. _Cargo: https://doc.rust-lang.org/cargo/
.. _rustup: https://rustup.rs/
.. _crates.io: https://crates.io/
