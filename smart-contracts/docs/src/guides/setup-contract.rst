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

Next is to add ``concordium-std`` as a dependency.
Which is a library for Rust containing procedural macros and functions for
writing small and efficient smart contracts.

You add the library by opening ``Cargo.toml`` and just below the line saying
``[dependencies]`` add a new line with ``concordium-std = "0.1"`` (or whichever
version is currently recommended).

.. code-block::

    [dependencies]
    concordium-std = "0.1"

The crate documentation can be found in docs.rs_.

.. note::
    If you wish to use a modified version, you will also have to clone the
    repository_ with ``concordium-std`` and have the dependency point at the
    directory instead, by adding the following to ``Cargo.toml``::

        [dependencies]
        concordium-std = { path = "./path/to/concordium-std" }

.. todo::
    Once the crate is released:

    - Verify the above is correct.
    - Remove the note.
    - Link crate documentation.

.. _Rust: https://www.rust-lang.org/
.. _Cargo: https://doc.rust-lang.org/cargo/
.. _rustup: https://rustup.rs/
.. _repository: https://gitlab.com/Concordium/concordium-std
.. _docs.rs: https://docs.rs/crate/concordium-std/

That is it! You are now ready to develop your own smart contract.
