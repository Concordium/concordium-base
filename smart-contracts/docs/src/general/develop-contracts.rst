.. _writing-smart-contracts:

====================================
Developing smart contracts in Rust
====================================

On the concordium blockchain smart contracts are deployed as Wasm modules, but
Wasm is designed as a compile target and is not suitable for writing by hand.
Instead we can write our smart contract in the Rust_ programming language,
which have good support for compiling to Wasm.

.. seealso::
    See :ref:`contract-module` for more about smart contract modules

A smart contract module is developed in Rust as a library crate, which is then
compiled to Wasm using the ``wasm32-unknown-unknown`` target.

Writing a smart contract using ``concordium_sc_base``
=====================================================

It is recommended to use the ``concordium_sc_base`` crate, which provides a
more Rust-like experience for developing smart contract modules and calling
host functions.

The crate allows to write ``init`` and ``receive``-functions as simple rust
functions annotated with ``#[init(...)]`` and ``#[receive(...)]`` respectively.

A simple counter example would look like:

.. code-block:: rust

    use concordium_sc_base::*;

    type State = u32;

    #[init(contract = "counter")]
    fn counter_init(
        _ctx: &impl HasInitContext<()>,
        _amount: Amount,
        _logger: &mut impl HasLogger,
    ) -> InitResult<State> {
        let state = 0;
        Ok(state)
    }

    #[receive(contract = "counter", name = "increment")]
    fn contract_receive<A: HasActions>(
        ctx: &impl HasReceiveContext<()>,
        _amount: Amount,
        _logger: &mut impl HasLogger,
        state: &mut State,
    ) -> ReceiveResult<A> {
        ensure!(ctx.sender().matches_account(&ctx.owner()); // Only the owner can increment
        *state += 1;
        Ok(A::accept())
    }

Here ``#[init(contract = "counter")]`` sets up the exported ``init``-function
for a contract we named ``"counter"``, it ensures the state is set properly
using host functions and the exported function follows the contract naming
convention.

The ``#[receive(contract = "counter", name = "increment")]`` supplies the
state to be manipulated directly.


.. _Rust: https://www.rust-lang.org/
.. _Cargo: https://doc.rust-lang.org/cargo/
.. _crates.io: https://crates.io/
