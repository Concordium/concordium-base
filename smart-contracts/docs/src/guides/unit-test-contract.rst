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

    use concordium_std::*;

    #[init(contract = "my_contract", payable, enable_logger)]
    fn contract_init(
        ctx: &impl HasInitContext<()>,
        amount: Amount,
        logger: &mut impl HasLogger,
    ) -> InitResult<State> { ... }

    #[receive(contract = "my_contract", name = "my_receive", payable, enable_logger)]
    fn contract_receive<A: HasActions>(
        ctx: &impl HasReceiveContext<()>,
        amount: Amount,
        logger: &mut impl HasLogger,
        state: &mut State,
    ) -> ReceiveResult<A> { ... }

Testing stubs for the function arguments can be found in a submodule of
``concordium-std`` called ``test_infrastructure``.

.. seealso::

    For more information and examples see the crate documentation of
    concordium-std.

.. todo::

    Show more of how to write the unit test

Running tests in Wasm
======================

Compiling the tests to native machine code is sufficient for most cases, but it
is also possible to compile the tests to Wasm and run them using the exact
interpreter that is used by the nodes.
This makes the test environment closer to the run environment on chain and could
in some cases catch more bugs.

The development tool ``cargo-concordium`` includes a test runner for Wasm, which
uses the same Wasm interpreter as the one shipped in the Concordium nodes.

.. seealso::

    For a guide of how to install ``cargo-concordium`` see :ref:`setup-tools`.

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
``concordium-std`` is compiled with the ``wasm-test`` feature, and otherwise
falls back to behave just like ``#[test]``, meaning it is still possible to run
unit tests targeting native code using ``cargo test``.

Similarly the macro ``#[concordium_cfg_test]`` includes our module when build
``concordium-std`` with ``wasm-test`` otherwise behaves like ``#[test]``,
allowing us to control when to include tests in the build.

Tests can now be build and run using::

    cargo concordium test

Which compiles the tests for Wasm with the ``wasm-test`` feature enabled for
``concordium-std`` and uses the test runner from ``cargo-concordium``.

.. warning::

    Error messages from ``panic!`` and therefore also the different variations
    of ``assert!``, are *not* shown when compiling to Wasm.

    Instead use ``fail!`` and the ``claim!`` variants to do assertions when
    testing, as these reports back the error messages to the test runner before
    failing the test.
    Both are part of ``concordium-std``.

.. todo::

    use link concordium-std: docs.rs/concordium-std when crate
    is published.
