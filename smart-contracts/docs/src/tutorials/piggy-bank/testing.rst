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
.. _HasActions: https://docs.rs/concordium-std/latest/concordium_std/trait.HasActions.html
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
.. _concordium_cfg_test: https://docs.rs/concordium-std/latest/concordium_std/attr.concordium_cfg_test.html
.. |concordium_cfg_test| replace:: ``#[concordium_cfg_test]``
.. _concordium_test: https://docs.rs/concordium-std/latest/concordium_std/attr.concordium_test.html
.. |concordium_test| replace:: ``#[concordium_test]``
.. _fail: https://docs.rs/concordium-std/latest/concordium_std/macro.fail.html
.. |fail| replace:: ``fail!``
.. _expect_report: https://docs.rs/concordium-std/latest/concordium_std/trait.ExpectReport.html#tymethod.expect_report
.. |expect_report| replace:: ``expect_report``
.. _expect_err_report: https://docs.rs/concordium-std/latest/concordium_std/trait.ExpectErrReport.html#tymethod.expect_err_report
.. |expect_err_report| replace:: ``expect_err_report``
.. _claim: https://docs.rs/concordium-std/latest/concordium_std/macro.claim.html
.. |claim| replace:: ``claim!``
.. _claim_eq: https://docs.rs/concordium-std/latest/concordium_std/macro.claim_eq.html
.. |claim_eq| replace:: ``claim_eq!``
.. _ensure: https://docs.rs/concordium-std/latest/concordium_std/macro.ensure.html
.. |ensure| replace:: ``ensure!``

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
part, either follow the previous part or copy the resulting code from there.

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
      todo!("Implement")
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

Putting it all together we end up with the following test for initializing a
piggy bank:

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

For testing we can represent the actions as a simple tree structure
|ActionsTree|_, making it easy to inspect.

.. note::

   The |receive| macro uses another representation of the actions, when building
   the smart contract module. This representation depends on functions supplied
   by the host environment and is therefore not suitable for unit tests.

Now we should inspect the function succeeded, verify the state and actions
produced. In our case the state should be still be intact and it should just
produce the action for accepting the GTU.

.. code-block:: rust

   let actions = match actions_result.expect("Inserting GTU results in error.");

   assert_eq!(actions, ActionsTree::accept(), "No action should be produced.");
   assert_eq!(state, PiggyBankState::Intact, "Piggy bank state should still be intact.");

The second test becomes:

.. code-block:: rust

   #[test]
   fn test_insert_intact() {
       let ctx = ReceiveContextTest::empty();
       let amount = Amount::from_micro_gtu(100);
       let mut state = PiggyBankState::Intact;

       let actions_result: ReceiveResult<ActionsTree> = piggy_insert(&ctx, amount, &mut state);

       let actions = match actions_result.expect("Inserting GTU results in error.");

       assert_eq!(actions, ActionsTree::accept(), "No action should be produced.");
       assert_eq!(state, PiggyBankState::Intact, "Piggy bank state should still be intact.");
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

Testing cause of rejection
==========================

We want to test that our piggy bank rejects in certain contexts, for example
when someone besides the owner of the smart contract tries to smash it.

The test should:

- Make a context where the sender and owner are two different accounts.
- Set the state to be intact.
- Call ``piggy_smash``.
- Check that the result is an error.

The test could look like this:

.. code-block:: rust

   #[test]
   fn test_smash_intact_not_owner() {
       let mut ctx = ReceiveContextTest::empty();
       let owner = AccountAddress([0u8; 32]);
       ctx.set_owner(owner);
       let sender = Address::Account(AccountAddress([1u8; 32]));
       ctx.set_sender(sender);
       let balance = Amount::from_micro_gtu(100);
       ctx.set_self_balance(balance);

       let mut state = PiggyBankState::Intact;

       let actions_result: ReceiveResult<ActionsTree> = piggy_smash(&ctx, &mut state);

       assert!(actions_result.is_err(), "Contract is expected to fail.")
   }

One thing to notice is that the test is not ensuring *why* the contract
rejected, our piggy bank might reject for a wrong reason, and this would be a
bug.
This is probably fine for a simple smart contract like our piggy bank, but for a
smart contract with more complex logic and many reasons for rejecting, it would
be better if we tested this as well.

To solve this we introduce a ``SmashError`` enum , to represent the different
reasons for rejection:

.. code-block:: rust

   #[derive(Debug, PartialEq, Eq)]
   enum SmashError {
       NotOwner,
       AlreadySmashed,
   }

To use this error type; the function ``piggy_smash`` should return ``Result<A,
SmashError>`` instead of ``ReceiveResult<A>``:

.. code-block:: rust
   :emphasize-lines: 5

   #[receive(contract = "PiggyBank", name = "smash")]
   fn piggy_smash<A: HasActions>(
       ctx: &impl HasReceiveContext,
       state: &mut PiggyBankState,
   ) -> Result<A, SmashError> {
      // ...
   }

and we also have to supply the |ensure| macros with a second argument, which is
the error to produce:

.. code-block:: rust
   :emphasize-lines: 9, 10

   #[receive(contract = "PiggyBank", name = "smash")]
   fn piggy_smash<A: HasActions>(
       ctx: &impl HasReceiveContext,
       state: &mut PiggyBankState,
   ) -> Result<A, SmashError> {
       let owner = ctx.owner();
       let sender = ctx.sender();

       ensure!(sender.matches_account(&owner), SmashError::NotOwner);
       ensure!(*state == PiggyBankState::Intact, SmashError::AlreadySmashed);

       *state = PiggyBankState::Smashed;

       let balance = ctx.self_balance();
       Ok(A::simple_transfer(&owner, balance))
   }

Since the return type have changed for the ``piggy_smash`` function, we have to
change the type in the tests as well:

.. code-block:: rust
   :emphasize-lines: 5, 14

   #[test]
   fn test_smash_intact() {
       // ...

       let actions_result: Result<ActionsTree, SmashError> = piggy_smash(&ctx, &mut state);

       // ...
   }

   #[test]
   fn test_smash_intact_not_owner() {
       // ...

       let actions_result: Result<ActionsTree, SmashError> = piggy_smash(&ctx, &mut state);

       // ...
   }

We can now check which error was produced in the test:

.. code-block:: rust
   :emphasize-lines: 15-16

   #[test]
   fn test_smash_intact_not_owner() {
       let mut ctx = ReceiveContextTest::empty();
       let owner = AccountAddress([0u8; 32]);
       ctx.set_owner(owner);
       let sender = Address::Account(AccountAddress([1u8; 32]));
       ctx.set_sender(sender);
       let balance = Amount::from_micro_gtu(100);
       ctx.set_self_balance(balance);

       let mut state = PiggyBankState::Intact;

       let actions_result: ReceiveResult<ActionsTree> = piggy_smash(&ctx, &mut state);

       let err = actions_result.expect_err("Contract is expected to fail.");
       assert_eq!(err, SmashError::NotOwner, "Expected to fail with error NotOwner")
   }

We leave it up to the reader to test, whether smashing a piggy bank, that have
already been smashed results in the correct error.

.. warning::

   On-chain, there is no way to tell for which reason a smart contract rejects,
   since the blockchain would not have any use of this information.
   Thus, introducing a custom error type is solely for the purpose of writing
   better tests.

Compiling and running tests in Wasm
===================================

When running ``cargo test`` our contract module and tests are compiled targeting
your native platform, but on the Concordium blockchain a smart contract module
is in Wasm.
Therefore it is preferable to compile the tests targeting Wasm and run the tests
using a Wasm interpreter instead.
Lucky for us, the ``cargo-concordium`` tool contains such an interpreter, and
it is the same interpreter shipped with the official nodes on the Concordium
blockchain.

Before we can run our tests in Wasm, we have to replace ``#[cfg(test)]`` at the
top of our test module with |concordium_cfg_test|_ and all the ``#[test]``
macros with |concordium_test|_.

.. code-block:: rust
   :emphasize-lines: 3, 8, 13, 18, 23

   // PiggyBank contract code up here

   #[concordium_cfg_test]
   mod tests {
       use super::*;
       use test_infrastructure::*;

       #[concordium_test]
       fn test_init() {
           // ...
       }

       #[concordium_test]
       fn test_insert_intact() {
           // ...
       }

       #[concordium_test]
       fn test_smash_intact() {
           // ...
       }

       #[concordium_test]
       fn test_smash_intact_not_owner() {
           // ...
       }
   }

We will also need to modify our tests a bit. Usually a test in Rust_ is failed
by panicking with an error message, but when compiling to Wasm this error
message is lost.
Instead we need generate code reporting the error back to the host, who is
running the Wasm, and to do so, |concordium-std| provides replacements:

- A call to ``panic!`` should be replace with |fail|_.
- The ``expect`` and ``expect_err`` method should be replaced with
  |expect_report|_ and |expect_err_report|_.
- ``assert`` and ``assert_eq`` should be replace with |claim|_ and |claim_eq|_
  respectively.

All of these macros are wrappers, which behaves the same as their counterpart
except when we build our smart contract for testing in Wasm using
``cargo-concordium``. This means we can still run tests for targeting native
using ``cargo test``.

.. code-block:: rust
   :emphasize-lines: 14, 16, 31, 33, 34, 51, 52, 53, 70, 71

   // PiggyBank contract code up here

   #[concordium_cfg_test]
   mod tests {
      use super::*;
      use test_infrastructure::*;

      #[concordium_test]
      fn test_init() {
          let ctx = InitContextTest::empty();

          let state_result = piggy_init(&ctx);

          let state = state_result.expect_report("Contract initialization failed.");

          claim_eq!(
                state,
                PiggyBankState::Intact,
                "Piggy bank state should be intact after initialization."
          );
      }

      #[concordium_test]
      fn test_insert_intact() {
          let ctx = ReceiveContextTest::empty();
          let amount = Amount::from_micro_gtu(100);
          let mut state = PiggyBankState::Intact;

          let actions_result: ReceiveResult<ActionsTree> = piggy_insert(&ctx, amount, &mut state);

          let actions = actions_result.expect_report("Inserting GTU results in error.");

          claim_eq!(actions, ActionsTree::accept(), "No action should be produced.");
          claim_eq!(state, PiggyBankState::Intact, "Piggy bank state should still be intact.");
      }

      #[concordium_test]
      fn test_smash_intact() {
          let mut ctx = ReceiveContextTest::empty();
          let owner = AccountAddress([0u8; 32]);
          ctx.set_owner(owner);
          let sender = Address::Account(owner);
          ctx.set_sender(sender);
          let balance = Amount::from_micro_gtu(100);
          ctx.set_self_balance(balance);

          let mut state = PiggyBankState::Intact;

          let actions_result: Result<ActionsTree, SmashError> = piggy_smash(&ctx, &mut state);

          let actions = actions_result.expect_report("Inserting GTU results in error.");
          claim_eq!(actions, ActionsTree::simple_transfer(&owner, balance));
          claim_eq!(state, PiggyBankState::Smashed);
      }

      #[concordium_test]
      fn test_smash_intact_not_owner() {
          let mut ctx = ReceiveContextTest::empty();
          let owner = AccountAddress([0u8; 32]);
          ctx.set_owner(owner);
          let sender = Address::Account(AccountAddress([1u8; 32]));
          ctx.set_sender(sender);
          let balance = Amount::from_micro_gtu(100);
          ctx.set_self_balance(balance);

          let mut state = PiggyBankState::Intact;

          let actions_result: Result<ActionsTree, SmashError> = piggy_smash(&ctx, &mut state);

          let err = actions_result.expect_err_report{"Contract is expected to fail.");
          claim_eq!(err, SmashError::NotOwner, "Expected to fail with error NotOwner")
      }
   }

Compiling and running the tests in Wasm can be done using:

.. code-block:: console

   $cargo concordium test

This will make a special test build of our smart contract module exporting all
of our tests as functions and it will then run each of these functions catching
the reported errors.

Simulating the piggy bank
=========================

So far the tests we have written are in Rust_ and have to be compiled alongside
the smart contract module in a test build, which is fine for unit testing, but
this test build is not the actual module that we intend to deploy on the
Concordium blockchain.

We should also test the smart contract wasm module meant for deployment, and we
can use the simulate feature of ``cargo-concordium``. It takes a smart contract
wasm module and uses the Wasm interpreter to run a smart contract function in a
given context.

For more on how to do this: check out the guide :ref:`local-simulate`.



.. First we need to build our piggy bank smart contract module using:

.. .. code-block:: console

..    $cargo concordium build --out piggy-module.wasm

.. We add ``--out piggy-module.wasm`` to output the smart contract Wasm module in
.. our current directory, making it more convenient to reference.

.. Simulate piggy bank initialization
.. ==================================

.. To simulate the initializing of a piggy bank instance, we use ``cargo concordium
.. run init`` given our smart contract module. We will also need to tell the
.. command which smart contract in the module to initialize and describe the
.. current context in a JSON file.

.. Although our piggy bank smart contract does not depend on the context for
.. initializing, the simulation tool still requires us to specify the context.
.. Create a file ``init-context.json`` with the following content:

.. .. code-block:: json

..    {
..        "metadata": {
..            "slotNumber": 1,
..            "blockHeight": 1,
..            "finalizedHeight": 1,
..            "slotTime": "2021-01-01T00:00:01Z"
..        },
..        "initOrigin": "3uxeCZwa3SxbksPWHwXWxCsaPucZdzNaXsRbkztqUUYRo1MnvF",
..        "senderPolicies": []
..    }

.. Most of these fields are not gonna be relevant for the piggy bank smart contract
.. and we refer the reader to :ref:`simulate-context` for a reference of what the
.. different fields mean.

.. We simulate the initialization of a piggy bank smart contract instance using the
.. following command:

.. .. code-block:: console

..    $cargo concordium run init --module piggy-module.wasm \
..                                --contract "PiggyBank" \
..                                --context init-context.json

.. The output should tell us the init call succeeded, and display the initial state
.. of our piggy bank to be a list of bytes, only containing the value 0.

.. This 0 represents the first variant in our ``PiggyBankState``, which is
.. ``Intact``, since this is how the derived serialization would write it. The
.. state ``Smashed`` is represented by the byte of value 1.

.. .. note::

..    As a smart contract developer it is important to understand how the contract
..    state is serialized. However, it is possible to have tools like
..    ``cargo-concordium`` represent the contract state using a more structured
..    representation using :ref:`schemas<contract-schema>`, but this is out of the
..    scope of this tutorial.

.. Simulate smashing a piggy bank
.. ==============================

