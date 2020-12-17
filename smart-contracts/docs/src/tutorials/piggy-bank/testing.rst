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
.. _HasInitContext: https://docs.rs/concordium-std/latest/concordium_std/trait.HasInitContext.html
.. |HasInitContext| replace:: ``HasInitContext``
.. _HasActions: https://docs.rs/concordium-std/latest/concordium_std/trait.HasAction.html
.. |HasActions| replace:: ``HasActions``
.. _ActionsTree: https://docs.rs/concordium-std/latest/concordium_std/test_infrastructure/enum.ActionsTree.html
.. |ActionsTree| replace:: ``ActionsTree``
.. _AccountAddress: https://docs.rs/concordium-std/latest/concordium_std/struct.AccountAddress.html
.. |AccountAddress| replace:: ``AccountAddress``
.. _set_owner: https://docs.rs/concordium-std/latest/concordium_std/test_infrastructure/type.ReceiveContextTest.html#method.set_owner
.. |set_owner| replace:: ``set_owner``
.. _Address: https://docs.rs/concordium-std/latest/concordium_std/enum.Address.html
.. |Address| replace:: ``Address``
.. _set_sender: https://docs.rs/concordium-std/latest/concordium_std/test_infrastructure/type.ReceiveContextTest.html#method.set_sender
.. |set_sender| replace:: ``set_sender``
.. _set_self_balance: https://docs.rs/concordium-std/latest/concordium_std/test_infrastructure/type.ReceiveContextTest.html#method.set_self_balance
.. |set_self_balance| replace:: ``set_self_balance``

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

Now we can start adding tests to this module.

Testing instantiation of a piggy bank
=====================================

The first test we add is to verify a piggy bank is set up with the correct
state.

.. code-block:: rust

   #[test]
   fn test_init() {

   }

As mentioned above, we test the initialization by calling the function
``piggy_init`` directly.
To construct its argument for, we use |InitContextTest|_, which provides a
placeholder for the context.

.. code-block:: rust

   let ctx = InitContextTest::empty();

Just as the name suggest, the test context is empty and if any of the getter
functions are called, it will make sure to fail the test, which should be fine
for now, since our piggy bank is not reading anything from the context.

.. note::

   As we will see later with the |ReceiveContextTest|_, these placeholders have
   setter functions, allowing us to partially specify the context.

Now we can call ``piggy_init`` and get a result containing the initial state.

.. code-block:: rust

   let state_result = piggy_init(&ctx);

First of all we want the test to fail, if our contract did not result in an
initial state:

.. code-block:: rust

       let state = state_result.expect("Contract initialization results in error.");

Next we assert the state is correctly set to ``Intact``:

.. code-block:: rust

   assert_eq!(
      state,
      PiggyBankState::Intact,
      "Piggy bank state should be intact after initialization."
   );

Putting it all together we end up with the following test for initializing a piggy
bank:

.. code-block:: rust

   // PiggyBank contract code up here

   #[cfg(test)]
   mod tests {
       use super::*;
       use test_infrastructure::*;

       #[test]
       fn test_init() {
           let ctx = InitContextTest::empty();

           let state_result = piggy_init(&ctx);

           let state = state_result.expect("Contract initialization results in error.");

           assert_eq!(
               state,
               PiggyBankState::Intact,
               "Piggy bank state should be intact after initialization."
           );
       }
   }

Run the test to check that it compiles and succeeds.

.. code-block:: console

   $cargo test



Test inserting GTU into a piggy bank
===========================================

Next we should test the different functions for interacting with a piggy bank.
This is done in the same way as initializing, except we use |ReceiveContextTest|
to construct the context.

To test ``piggy_insert`` we also need some amount of GTU and the current state
of our smart contract instance:

.. code-block:: rust

   let ctx = ReceiveContextTest::empty();
   let amount = Amount::from_micro_gtu(100);
   let mut state = PiggyBankState::Intact;

When calling ``piggy_insert`` we get back a result with actions, instead of an
initial as with ``piggy_init``. But we will need to help the compiler with
inferring which type to use for the generic ``A`` implementing |HasActions|_, so
we add the result type ``ReceiveResult<ActionsTree>``:

.. code-block:: rust

   let actions_result: ReceiveResult<ActionsTree> = piggy_insert(&ctx, amount, &mut state);

For testing we can represent the actions as a simple tree structure |ActionsTree|_, making it
easy to inspect.

.. note::

   The |receive| macro uses another representation of the actions, when building
   the smart contract module. This representation depends on functions supplied
   by the host environment and is therefore not suitable for unit tests.

Now we should inspect the function succeeded, verify the state and actions
produced. In our case the state should be still be intact and it should just
produce the action for accepting the GTU.

.. code-block:: rust

   let actions = match actions_result.expect("Inserting GTU results in error.");

   assert_eq!(state, PiggyBankState::Intact, "Piggy bank state should still be intact.");
   assert_eq!(actions, ActionsTree::accept(), "No action should be produced.");

The second test becomes:

.. code-block:: rust

   #[test]
   fn test_insert_intact() {
       let ctx = ReceiveContextTest::empty();
       let amount = Amount::from_micro_gtu(100);
       let mut state = PiggyBankState::Intact;

       let actions_result: ReceiveResult<ActionsTree> = piggy_insert(&ctx, amount, &mut state);

       let actions = match actions_result.expect("Inserting GTU results in error.");

       assert_eq!(state, PiggyBankState::Intact, "Piggy bank state should still be intact.");
       assert_eq!(actions, ActionsTree::accept(), "No action should be produced.");
   }

Again we should verify everything compiles and the tests succeeds using ``cargo
test``.

Next we could add a test, checking that inserting into a piggy bank with state
``Smashed`` results in an error, but we have been through everything needed to
do this, and we therefore leave as an exercise for the reader.

Test smashing a piggy bank
==========================

Testing ``piggy_smash`` will follow the same pattern, but this time we will need
to populate the context, since this function uses the context for getting the
contract owner, the sender of the message triggering the function and the
balance of contract.

If we just supply the function with an empty context it will fail, so instead we
define the context as mutable:

.. code-block:: rust

   let mut ctx = ReceiveContextTest::empty();

We create an |AccountAddress|_ to represent the owner and use the setter
|set_owner| implemented on |ReceiveContextTest|_:

.. code-block:: rust

   let owner = AccountAddress([0u8; 32]);
   ctx.set_owner(owner);

.. note::

   Notice we created the account address using an array of 32 bytes, which is
   how account addresses are represented on the Concordium blockchain.
   These byte arrays can also be represented as a base58check encoding, but for
   testing it is usually more convenient to specify addresses directly in bytes.

Next we set the sender to be the same address as the owner using |set_sender|_.
Since the sender can be a contract instance as well, we must wrap the owner
address in the |Address|_ type:

.. code-block:: rust

   let sender = Address::Account(owner);
   ctx.set_sender(sender);

Lastly we will need to set the current balance of the piggy bank instance, using
|set_self_balance|_.

.. code-block:: rust

   let balance = Amount::from_micro_gtu(100);
   ctx.set_self_balance(balance);

Now that we have the test context setup, we call the contract function
``piggy_smash`` and inspect the resulting action tree and state just like we did
in the previous tests:

.. code-block:: rust

   #[test]
   fn test_smash_intact() {
       let mut ctx = ReceiveContextTest::empty();
       let owner = AccountAddress([0u8; 32]);
       ctx.set_owner(owner);
       let sender = Address::Account(owner);
       ctx.set_sender(sender);
       let balance = Amount::from_micro_gtu(100);
       ctx.set_self_balance(balance);

       let mut state = PiggyBankState::Intact;

       let actions_result: ReceiveResult<ActionsTree> = piggy_smash(&ctx, &mut state);

       let actions = actions_result.expect("Inserting GTU results in error.");
       assert_eq!(actions, ActionsTree::simple_transfer(&owner, balance));
       assert_eq!(state, PiggyBankState::Smashed);
   }

Ensure everything compiles and the tests succeeds using ``cargo test``.

A few more tests can be written for the smashing function of our piggy bank, but
it would not introduce any new concepts, and these are left to the reader.

Compile and running tests in Wasm
=================================
