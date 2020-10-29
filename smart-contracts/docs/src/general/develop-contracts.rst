.. _writing-smart-contracts:

====================================
Developing smart contracts in Rust
====================================

On the concordium blockchain smart contracts are deployed as Wasm modules, but
Wasm is not suitable for writing by hand.
Instead we can write our smart contract in the Rust_ programming language,
which have good support for compiling to Wasm.

.. seealso:: For more on this see :ref:`contracts-on-chain`

A smart contract module is developed in Rust as a library crate, which is then
compiled to Wasm using the ``wasm32-unknown-unknown`` target.

Writing a smart contract
====================================

It is recommended to use the ``concordium_sc_base`` crate, which provides a
more Rust-like experience for developing smart contract modules and calling
host functions.

The crate allows to write ``init`` and ``receive``-functions as simple rust
functions annotated with ``#[init(...)]`` and ``#[receive(...)]`` respectively.

A simple counter example would look like:

.. code-block:: rust

    use concordium_sc_base::*;

    type State = u32;

    #[init(name = "counter")]
    fn counter_init<I: HasInitContext<()>, L: HasLogger>(
        _ctx: &I,
        _amount: Amount,
        _logger: &mut L,
    ) -> InitResult<State> {
        let state = 0;
        Ok(state)
    }

    #[receive(name = "counter_increment")]
    fn contract_receive<R: HasReceiveContext<()>, L: HasLogger, A: HasActions>(
        ctx: &R,
        _amount: Amount,
        _logger: &mut L,
        state: &mut State,
    ) -> ReceiveResult<A> {
        ensure!(ctx.sender().matches_account(&ctx.owner()), "Only the owner can increment.");
        *state += 1;
        Ok(A::accept())
    }

Here ``#[init(name = "counter")]`` sets up the exported ``init``-function
and name it ``"counter"``, it ensures the state is set properly using host
functions.
Likewise ``#[receive(name = "counter_increment")]`` supplies the state to be
manipulated directly.

.. _compiling-smart-contracts:

Compiling to Wasm
====================================

To help building small smart contract modules and to take advantage of features
such as contract schemas, we recommend using the ``cargo-concordium`` tool for
building rust smart contracts.
Install the tool by running::

    cargo install cargo-concordium

.. note::
    Until the tool is release on crates.io_, you instead have to clone
    the repo containing ``cargo-concordium`` and from the directory
    ``cargo-concordium`` run::

        cargo install --path .

.. todo::
    Once the tool is released:

    - Verify the above is correct.
    - Remove the note.

The ``cargo-concordium`` tool includes various utils for developing smart
contracts, such as testing and generating schemas, so in order to build run::

    cargo concordium build

.. todo:: Link contract schemas and the cargo-concordium tool

This uses Cargo_ for building, but runs further optimizations on the result.

.. warning::
    Although it is *not* recommended, it is possible to compile using Cargo_
    directly by running::

        cargo build --target=wasm32-unknown-unknown [--release]

    But even with the ``--release`` set, the produced Wasm module includes debug
    information and in some cases embed paths.

    .. todo::
        Maybe elaborate or add some link to an explanation.


Testing
====================================



.. _Rust: https://www.rust-lang.org/
.. _Cargo: https://doc.rust-lang.org/cargo/
.. _crates.io: https://crates.io/
