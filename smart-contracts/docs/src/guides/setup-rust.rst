.. _setup_rust:

=========================================
Setup for development
=========================================
Before we can start developing smart contracts, we need to install and setup a
environment.

Rust and Cargo
======================
First install rustup_, which will install both Rust_ and Cargo_ on your
machine.
Then use ``rustup`` to install the Wasm target::

    rustup target add wasm32-unknown-unknown

Cargo Concordium
======================
Next install the Concordium smart contract tool ``cargo-concordium`` by
running::

    cargo install cargo-concordium

.. note::
    Until the tool is release on crates.io_, you instead have to clone
    the repo containing ``cargo-concordium`` and from the directory
    ``cargo-concordium`` run::

        cargo install --path .

Concordium Client
======================
To be able to deploy smart contract and generally interacting with the chain,
make sure to have ``concordium-client`` install on your local system.

.. todo::
    Link to install instructions


.. _Rust: https://www.rust-lang.org/
.. _Cargo: https://doc.rust-lang.org/cargo/
.. _rustup: https://rustup.rs/
.. _crates.io: https://crates.io/
