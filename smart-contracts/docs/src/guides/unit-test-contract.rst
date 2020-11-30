.. _unit-test-contract:

=============================
Unit test a contract in Rust
=============================

This guide will show you how to write unit tests for a smart contract written in
Rust.
For testing a smart contract Wasm module see :ref:`local-simulate`.

A smart contracts in Rust is written as a library and we can unit test like a
library by annotating functions with a ``#[test]`` attribute.

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
target (most likely ``x86_64``), and run them. This kind of testing can be useful in
initial development and for testing functional correctness. But because there
are a number of differences in the different platforms, for example `wasm32` is
a 32-bit platform, meaning pointers are 4 bytes, comprehensive testing should
involve testing on the target platform.

Writing unit tests
====================

The structure of a unit test is usually setting up some state, running some unit
of code, followed by a number of assertions about the state and output of the
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
    concordium-sc-base.

.. todo::

    Show more of how to write the unit test

Running tests in Wasm
======================

Compiling the tests to machine code is sufficient for most cases, but it is also
possible to compile the tests to Wasm and run them using the exact intepreter
that is used by the nodes.
This makes the test environment closer to the run environment on chain and could
in some cases catch more bugs.

The development tool ``cargo-concordium`` includes a test runner for Wasm, which
uses the same Wasm interpreter as the one shipped in the Concordium nodes.

.. seealso::

    For a guide of how to install ``cargo-concordium`` see :ref:`setup-tools`.

First we need to add a ``wasm-test`` feature to the ``Cargo.toml``::

    ...
    [features]
    wasm-test = []
    ...

The unit test have to be annotated with ``#[concordium_test]`` instead of
``#[test]`` and we use ``#[concordium_cfg_test]`` instead of ``#[cfg(test)]``:

.. code-block:: rust

    // contract code
    ...

    #[concordium_cfg_test]
    mod test {

        #[concordium_test]
        fn some_test() { ... }

        #[concordium_test]
        fn another_test() { ... }
    }

The ``#[concordium_test]`` macro sets up our tests to be run in Wasm, when
compiled with the ``wasm-test`` feature, and otherwise falls back to behave just
like ``#[test]``, meaning it is still possible to run unit tests targeting
native code using ``cargo test``.

The macro ``#[concordium_cfg_test]`` is just an alias for ``#[cfg(any(test,
feature="wasm-test))]``, allowing us to control when to include tests in the
build.

Tests can now be build and run using::

    cargo concordium test

Which compiles the tests for Wasm with the ``wasm-test`` feature enabled and
uses the test runner from ``cargo-concordium``.

.. warning::

    Error messages from ``panic!`` and therefore also the different variations
    of ``assert!``, are *not* shown when compiling to Wasm.

    Instead use ``fail!`` and the ``claim!`` variants to do assertions when
    testing, as these reports back the error messages to the test runner before
    failing the test.
    Both are part of ``concordium-sc-base``.

.. todo::

    use link concordium-sc-base: docs.rs/concordium-sc-base when crate
    is published.
