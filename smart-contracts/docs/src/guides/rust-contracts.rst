.. _writing-smart-contracts:

====================================
Smart Contracts in Rust
====================================

In Rust_ a smart contract is written as an ordinary Rust library package, which
is then compile to target ``wasm-unknown-unknown``.
It uses Cargo_ for compilation and dependency management.


Installation
====================================

First install rustup_, which will install both Rust_ and Cargo_ on your
machine.
Then use rustup to install the Wasm target::

    rustup target add wasm32-unknown-unknown

Next install the Concordium Smart Contract tool ``cargo-concordium`` by
running::

    cargo install cargo-concordium

.. note::
    Until the tool is release on crates.io_, you will also have to clone
    the repo containing ``cargo-concordium`` and from the directory
    ``cargo-concordium`` run::

        cargo install -path .

.. todo::
    Once the tool is released:

    - Verify the above is correct.
    - Remove the note.

Getting started
=====================================

To setup a new smart contract project, first create a project directory, inside
the project directory run the following in a terminal::

    cargo init --lib

This will setup a default Rust library project.

Next is to add the dependency ``concordium-sc-base`` which is the official
standard library for developing smart contract.
Open the ``Cargo.toml`` file and add the following dependency::

    [dependencies]
    concordium-sc-base = "1.0.0"

.. note::
    Until the dependency is release on crates.io_, you will also have to clone
    the repo with ``concordium-sc-base`` and instead add the following to
    ``Cargo.toml``::

        [dependencies]
        concordium-sc-base = { path = "./path/to/concordium-sc-base" }

.. todo::
    Once the crate is released:

    - Verify the above is correct.
    - Remove the note.
    - Link crate documentation.

This library contains useful macros for writing small and efficient smart
contracts.

.. todo::
    Explain how to write a basic contract in ``src/lib.rs``

Building
====================================




.. todo::
    write section

Schema
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. todo::
    write section

Testing
====================================

.. todo::
    write section

Examples
====================================



.. _Rust: https://www.rust-lang.org/
.. _Cargo: https://doc.rust-lang.org/cargo/
.. _rustup: https://rustup.rs/
.. _crates.io: https://crates.io/
