.. _setup-contract:

=============================
Setup a contract project
=============================

A Smart contracts in Rust is written as an ordinary Rust library crate.
The library is then compiled to Wasm using the Rust target
``wasm32-unknown-unknown`` and since it is just a Rust library, we can use
Cargo_ for dependency management.

To setup a new smart contract project, first create a project directory, inside
the project directory run the following in a terminal::

    cargo init --lib

This will setup a default Rust library project by creating a few files and
folders.
Your directory should now contain a ``Cargo.toml`` file and a ``src``
directory and some hidden files.

Next is to add ``concordium-sc-base`` as a dependency.
Which is a library for Rust containing procedural macros and functions for
writing small and efficient smart contracts.

You add the library by opening ``Cargo.toml`` and just below the line saying
``[dependencies]`` add a new line with ``concordium-sc-base = "1.0.0"``.

.. code-block::

    [dependencies]
    concordium-sc-base = "1.0.0"

.. note::
    Until the dependency is released on crates.io_, you will also have to clone
    the repository_ with ``concordium-sc-base`` and have the dependency to point at
    the directory instead, by adding the following to ``Cargo.toml``::

        [dependencies]
        concordium-sc-base = { path = "./path/to/concordium-sc-base" }

.. todo::
    Once the crate is released:

    - Verify the above is correct.
    - Remove the note.
    - Link crate documentation.

.. _Rust: https://www.rust-lang.org/
.. _Cargo: https://doc.rust-lang.org/cargo/
.. _rustup: https://rustup.rs/
.. _crates.io: https://crates.io/
.. _repository: https://gitlab.com/Concordium/smart-contracts


That is it! You are now ready to develop your own smart contract.
