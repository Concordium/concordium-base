.. Should cover:
.. - Unit testing in native
.. - Unit testing in Wasm
.. - Custom error
.. - Simulating locally

.. _Rust: https://www.rust-lang.org/
.. _concordium-std: https://docs.rs/concordium-std/latest/concordium_std/index.html
.. |concordium-std| replace:: ``concordium-std``
.. _test_infrastructure: https://docs.rs/concordium-std/latest/concordium_std/test_infrastructure/index.html
.. |test_infrastructure| replace:: ``test_infrastructure``
.. _init: https://docs.rs/concordium-std/latest/concordium_std/attr.init.html
.. |init| replace:: ``#[init]``
.. _receive: https://docs.rs/concordium-std/latest/concordium_std/attr.receive.html
.. |receive| replace:: ``#[receive]``
.. _InitContextTest: https://docs.rs/concordium-std/latest/concordium_std/test_infrastructure/type.InitContextTest.html
.. |InitContextTest| replace:: ``InitContextTest``
.. _ReceiveContextTest: https://docs.rs/concordium-std/latest/concordium_std/test_infrastructure/type.ReceiveContextTest.html
.. |ReceiveContextTest| replace:: ``ReceiveContextTest``

.. _piggy-bank-testing:

=====================================
Testing the piggy bank smart contract
=====================================

This is the second :ref:`part of a tutorial<piggy-bank>` on smart contract
development.
So far we have written a piggy bank smart contract in the Rust_ programming
language.
This part will focus on how we can write unit test for our piggy bank smart
contract and how to setup and locally simulate an invocation of a smart
contract.

.. warning::

   The reader is assumed to have basic knowledge of what a blockchain and smart
   contract is, and some experience with Rust_.

.. contents::
   :local:
   :backlinks: None

.. todo::

   Link the repo with the final code.

Preparation
===========

Before we start, make sure to have the necessary tooling for building Rust
contracts.
The guide :ref:`setup-tools` will show you how to do this.
Also, make sure to have a text editor setup for writing Rust.

Since we are going to extend the smart contract code written in the previous
part, either follow the previous part or copy the resulting code from here.

.. todo::

   Add link to 'here' for the code from the previous part.

We are now ready for writing unit tests for our smart contract!

Adding a test module
========================

Since a smart contract module is written as a Rust library, we can test it as
one would test any library and write unit-tests as part of the Rust module.

At the bottom of the ``lib.rs`` file containing our code, make sure you have the
following starting point:

.. code-block:: rust

   // PiggyBank contract code up here

   #[cfg(test)]
   mod tests {
       use super::*;

   }

This is our test module, which is a common pattern for writing unit tests in
Rust, so we will not spend time on explaining any of the above code.

We test the contract functions just as if they were regular functions, by
calling the functions we have annotated with |init|_ and |receive|_.

But in order to call them, we will need to first construct the arguments.
Luckily |concordium-std|_ contains a submodule |test_infrastructure|_ with
stubs for this, so let us first bring everything from the submodule into scope.

.. code-block:: rust
   :emphasize-lines: 4

   #[cfg(test)]
   mod tests {
       use super::*;
       use test_infrastructure::*;

   }

Now let us start adding unit tests to this module.

Testing instantiation of a piggy bank
=====================================

The first unit test we add is to test a piggy bank is set up with the correct
state.

.. code-block:: rust

   #[test]
   fn test_init() {
       let ctx = InitContextTest::empty();
       let result = piggy_init(&ctx);

       let state = match result {
           Ok(state) => state,
           Err(_) => fail!("Contract initialization failed."),
       };

       claim_eq!(
           state,
           PiggyBankState::Intact,
           "Piggy bank state should be intact after initialization."
       );
   }
