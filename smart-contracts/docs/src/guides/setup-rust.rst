.. _setup_rust:

=============================
Install tools for development
=============================
Before we can start developing smart contracts, we need to install and setup a
environment.

Rust and Cargo
==============
First install rustup_, which will install both Rust_ and Cargo_ on your
machine.
Then use ``rustup`` to install the Wasm target, which is used by for
compilation::

    rustup target add wasm32-unknown-unknown

Cargo Concordium
================
The tool for developing smart contracts for the Concordium blockchain.
It can be used for :ref:`compiling<compiling-smart-contracts>` and testing
smart contracts, and enables features such as contract schemas.

.. todo::
    Add links for testing and schemas.

It is installed by running::

    cargo install cargo-concordium

.. note::
    Until the tool is release on crates.io_, you instead have to clone
    the repo containing ``cargo-concordium`` and from the directory
    ``cargo-concordium`` run::

        cargo install --path .

For a description of how to use the tool run::

    cargo concordium --help

Concordium Client
=================
To be able to deploy smart contract and generally interacting with the chain,
make sure to have ``concordium-client`` install on your local system.

.. todo::
    Link to install instructions


.. _Rust: https://www.rust-lang.org/
.. _Cargo: https://doc.rust-lang.org/cargo/
.. _rustup: https://rustup.rs/
.. _crates.io: https://crates.io/
