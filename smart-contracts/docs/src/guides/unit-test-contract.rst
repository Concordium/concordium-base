.. _unit-test-contract:

=============================
Unit test a contract in Rust
=============================

This guide will show you how to write unit tests for a smart contract written in
Rust.
For testing a smart contract Wasm module see :ref:`local-simulate`.

a smart contracts in Rust is written as a library and we can unit test like a
library by having a test module in the same file as our contract.

.. code-block:: rust

    // contract code
    ...

    #[cfg(test)]
    mod test {

        #[test]
        fn some_test() { ... }

        #[test]
        fn another_test() { ... }
    }

Running the test can be done using ``cargo``::

    cargo test

Which by default compiles the contract and tests to machine code for your local
machine and run them.

Writing unit tests
====================

The structure of a unit test is usually setting up some state, running some unit
of code, followed by a bunch of assertions about the state and output of the
code.

If the contract functions are written using ``#[init(..)]`` or
``#[receive(..)]``, we can test these functions directly in the unit test.

.. code-block:: rust

    use concordium_sc_base::*;

    #[init(contract = "my_contract")]
    fn contract_init(
        ctx: &impl HasInitContext<()>,
        amount: Amount,
        logger: &mut impl HasLogger,
    ) -> InitResult<State> { ... }

    #[receive(contract = "my_contract", name = "my_receive")]
    fn contract_receive<A: HasActions>(
        ctx: &impl HasReceiveContext<()>,
        amount: Amount,
        logger: &mut impl HasLogger,
        state: &mut State,
    ) -> ReceiveResult<A> { ... }

Testing stubs for the function arguments can be found in a submodule of
``concordium-sc-base`` called ``test_infrastructure``.

.. seealso::

    For more information and examples see the crate documentation of
    concordium-sc-base_.

.. todo::

    Show more of how to write the unit test

Running tests in Wasm
======================

Compiling the tests to machine code is sufficient for most cases, but it is also
possible to compile the tests to Wasm and use a custom test runner for running
the Wasm code.
This makes the test environment closer to the run environment on chain and could
in some cases catch more bugs.

The development tool ``cargo-concordium`` includes a test runner for Wasm, which
uses the same Wasm interpreter as the one shipped in the Concordium nodes.

.. seealso::

    For a guide of how to install ``cargo-concordium`` see :ref:`setup-tools`.

To set ``cargo-concordium`` as the test runner, create the file
``.cargo/config`` and add the following::

    [target.wasm32-unknown-unknown]
    runner = ["cargo", "concordium", "test", "--source"]

Now you can run the test with Wasm as the target::

    cargo test --target=wasm32-unknown-unknown

Which compiles the tests for Wasm and uses the test runner from
``cargo-concordium``.

.. warning::

    Error messages from ``panic!`` and therefore also the different variations
    of ``assert!``, are *not* shown when compiling to Wasm.

    Instead use ``fail!`` and the ``claim!`` variants to do assertions when
    testing, as these reports back the error messages to the test runner before
    failing the test.
    Both are part of concordium-sc-base_.


.. _concordium-sc-base: https://docs.rs/concordium-sc-base
