.. highlight:: rust

.. _first-contract:

================================
My first smart contract: Counter
================================

In this tutorial, we are going to build a minimal smart contract.
The goal is to give you a run-through every part of the contract development
process.
You will learn the basics of how to setup, write, build, test and deploy a
smart contract using Rust.

.. warning::

   The reader is assumed to have basic knowledge of what a blockchain and smart
   contract is, and some experience with the Rust programming language.

Preparation
===========

Before we start, make sure to have the necessary tooling for building Rust
contracts.
The guide :ref:`setup-tools` will show you how to do this.
Also, make sure to have a text editor setup for writing Rust.

We also need to setup a new smart contract project.
Follow the guide :ref:`setup-contract` and return to this point afterwards.

Counter contract
================

We are now ready for writing our first smart contract for the Concordium
blockchain.

The contract we are going to build in this tutorial is going to act as a
counter, which starts at 0, and exposes a function for incrementing its value.
Since contracts and instances are publicly available, we also want to require
that the counter can only be incremented by the owner of the instance.

The contract itself is not that interesting nor even a realistic use case of
smart contracts, but it is easy to understand and it is enough for us to try the
whole process of contract development.

Standard library
================

The source code of our smart contract is going to be in the ``src`` directory,
which already contains the file ``lib.rs``, assuming you follow the above guide
to setup your project.
Open ``src/lib.rs`` in your editor and you'll see some code for writing tests,
which you can delete for now. We will come back to tests later in this tutorial.

First, we bring everything from the ``concordium-std`` library into scope,
by adding the line::

   use concordium_std::*;

This library contains everything needed for writing our smart contract.
It provides convenient wrappers around some low-level operations making our code
more readable.

Specifying the contract state
=============================

First, we specify the type of the contract state. The contract state could be
any type and is typically a ``struct`` or an ``enum``.
Since our contract is going to be a simple counter, we just let the state be an
unsigned integer::

   type State = u32;

On the blockchain, the state of a smart contract is represented by an array of
bytes, and it is important that our contract state is serializable to bytes.
When using the ``concordium-std`` library, this all boils down to our type
for the contract state having to implement the ``Serialized`` trait from
``concordium-std``.

Luckily the library already contains implementations for most of the primitives
and standard types in Rust, meaning ``u32`` already implements the trait, so no
more work is necessary for the state.

.. todo::

   Link to more information.

The ``init``-function
=====================

A smart contract must specify an ``init``-function, which is called when new
instances of the contract are created, and is used to setup the initial state of
the contract instance.

.. note::
   If you have experience with Object-Oriented Programming, it might help to
   think of a smart contract as a *class*, the ``init``-function as a
   *constructor* and smart contract instances as *objects*.

In the case our the counter, the ``init``-function should set the initial state
to 0.
But before going into the details, have a look at the resulting code of writing
the ``init``-function for our counter contract::

   #[init(contract = "counter")]
   fn counter_init(
      _ctx: &impl HasInitContext<()>,
   ) -> InitResult<State> {
      let state = 0;
      Ok(state)
   }

The ``#[init(..)]`` macro
=========================

In Rust an ``init``-function can be specified as a regular function, annotated
with the procedural macro from ``concordium_std`` called ``#[init(..)]``.
The macro saves you from some details of setting up the function as an
external function and supplies a nicer interface for accessing information and
logging events.

You are required to set the ``contract`` attribute of the macro, which is going
to be the name of the exposed ``init``-function and therefore visible on the
chain with "init\_" as prefix.

Unsurprisingly, we choose to call our contract "counter".

The function only takes one argument ``ctx``, which is an object with a number
of getter functions for accessing information about the current context, such as
who invoke this function, the argument supplied and the current state of the
chain.

The return type of our function is ``InitResult<State>``, which is an alias for
``Result<State, Reject>``.

The function body should set our counter state to 0, which is straight forward.

.. Avoiding black holes
.. ====================
.. As we are not going to specify a way to extract GTU from this contract, the
.. GTU send to an instance of the contract will be trapped.
.. It is easy to create smart contracts, which acts as black holes
.. preventing the GTU send to them from being accessible *ever* again.

.. To prevent this, we let the contract instantiation fail if a non-zero amount
.. is sent to it. We do this with the ``ensure_eq!`` macro, which is given
.. two arguments to compare for equality, if *not* equal it will make the
.. contract reject the instantiation

..     ensure_eq!(amount.micro_gtu, 0);

Testing instantiation
=====================

A smart contract can be tested at several levels, which is described in detail
<here>.
In this tutorial, we will only cover unit tests.

.. todo::

   Insert reference for contract testing

Since a smart contract is written as a Rust library, we can test it as one would
test any library and write unit-tests as part of the Rust module.
At the bottom of our contract, make sure you have the following starting point::

   #[cfg(test)]
   mod tests {
       use super::*;

       #[test]
       fn test_init() {

       }
   }

This is our test module, which is a common pattern for writing unit tests in
Rust, so we will not spend time on explaining any of the above code.

For our first test, we wish to call the ``counter_init`` function as just a
regular function, but we first need a way to construct the argument.
Luckily ``concordium_std`` contains a submodule ``test_infrastructure`` with
stubs for this, so let us first bring everything from the submodule into scope.

.. code-block:: rust
   :emphasize-lines: 4

   #[cfg(test)]
   mod tests {
       use super::*;
       use test_infrastructure::*;

       #[test]
       fn test_init() {

       }
   }

To construct the argument for ``counter_init``, we use
``InitContextTest::empty()``, which is a stub for the context::

   let ctx = InitContextTest::empty();

As hinted by ``empty``, the name of the constructor, our context is empty, and
if the contract tries to access anything in the context the test will fail.
This will be fine for now, since our contract does not access the context during
initialization.
You will see how to create a non-empty context a bit later in this tutorial.

.. The second argument is the amount included with the transfer at
.. initialization.
.. On chain this is represented in microGTU as a ``u64``, but in Rust it is
.. wrapped in a more convenient type for added type-safety.

..     let amount = Amount::from_micro_gtu(0);

.. For the third argument, we need to specify a *logger* and from
.. ``test_infrastructure`` we get the ``LogRecorder`` which collects all the
.. contract event logs into a ``Vec`` that we later can inspect after running
.. our function

..     let mut logger = LogRecorder::init();

.. We will not use the logger for anything in this tutorial, but to learn more
.. see here.


With the argument constructed we can now call our function and get back
a result::

   let result = counter_init(&ctx);

Now we should inspect the result and ensure everything is as expected.
First, we match on the result to unwrap the state created if result is ``Ok``.
If instead the result is an ``Err``, we fail the test with an error message::

   let state = match result {
       Ok(state) => state,
       Err(_) => fail!("Contract initialization failed.")
   };

We use ``fail!`` to fail the test.
This is a small wrapper around ``panic!`` which is designed for use with the
``wasm32`` target.

.. note::

   ``fail!`` solves an issue with reporting errors, when tests are compiled to
   Wasm, and behaves just like ``panic!`` when compiled to native code.


You might wonder why ``fail!`` uses ``panic!`` when we said it was better *not*
to panic earlier in this tutorial.
The difference between now and then, is that now we are writing tests, and
testing in Rust uses panic to fail and will not be included in our smart
contract when we build it for release.

Lastly, we check if the state is set to 0, using ``claim_eq!``, which, similar
to ``fail!``, is a wrapper around ``assert_eq!``, solving some error reporting::

   claim_eq!(state, 0, "Initial count set to 0");

Altogether the test should look something like this::

   #[test]
   fn test_init() {
      // Setup
      let ctx = InitContextTest::empty();

      // Call the init function
      let result = counter_init(&ctx);

      // Inspect the result
      let state = match result {
         Ok(state) => state,
         Err(_) => fail!("Contract initialization failed."),
      };
      claim_eq!(state, 0, "Initial count set to 0");
   }

We can compile the test to native code and run it, by executing the following in
a terminal:

.. code-block:: console

   $cargo test

It should run one test, and hopefully it succeeds.


``receive``-functions
=====================

We have now defined how instances of our smart contract are created, and our
smart contract is in principle a valid contract at this point.
However, we would also like to define how to interact with instances of our
contract.
Specifically, a way to increment the counter, and recall the requirement of only
allowing the contract owner to increment.

A smart contract can expose zero or more functions for interacting with an
instance.
These functions are called ``receive``-functions, and can read and
write to the state of the instance, access the state of the blockchain and
return a description of actions to be executed on-chain.

.. note::

   A continuation of the analogy to Object Oriented Programming:
   ``receive``-functions corresponds to object methods.

There are 3 types of actions possible in the description:

   * **Accept**: Accept incoming GTU. Always succeeds.
   * **Simple Transfer**: Transfer some amount of GTU from the balance of the
     smart contract instance to an account.
   * **Send**: Trigger ``receive``-function of a smart contract instance, with
     a parameter and an amount of GTU.

and two ways to compose actions:

   * **And**: Runs the first action, if it succeeds runs the second action,
     otherwise results in rejection.
   * **Or**: Runs the first action, **if it fails**, runs the second action,
     otherwise results in success.

Our simple counter contract is only going to use **Accept**, but we refer the
reader to :ref:`contract-instance-actions` for more information on this topic.

Again, have a look at the code before we start explaining things::

   #[receive(contract = "counter", name = "increment")]
   fn contract_receive<A: HasActions>(
      ctx: &impl HasReceiveContext<()>,
      state: &mut State,
   ) -> ReceiveResult<A> {
      // Assertions
      let sender = ctx.sender();
      let owner = ctx.owner();
      ensure!(sender.matches_account(&owner)); // Only the owner can increment.

      // Update the contract state
      *state += 1;

      Ok(A::accept())
   }


The ``#[receive(...)]`` macro
=============================

Specifying ``receive``-functions in Rust, can be done using the procedural macro
``#[receive(...)]``, which, like ``#[init(...)]``, sets up an external function
and supplies us with an interface for accessing the context of the chain and for
logging events.
But, unlike the ``#[init(...)]`` macro, the function for ``#[receive(...)]`` is
also supplied with a mutable reference to the current state of the instance.

The macro requires the name of the contract using the ``contract`` attribute,
which should match the name in the corresponding attribute in ``#[init(...)]``
(``counter`` in our case), and a name for this ``receive``-function, which we
choose to be ``increment``::

   #[receive(contract = "counter", name = "increment")]

The return type of the function is ``ReceiveResult<A>``, which is an alias for
``Result<A, Reject>``.
Here ``A`` implements ``HasActions``, which exposes functions for creating the
different actions.

.. Again we ensure that *no* amount of GTU was send to the balance of this
.. contract

..     ensure_eq!(amount.micro_gtu, 0); // The amount must be 0.

We ensure only the owner can increment, by checking if the sender is the
owner account.
The sender can be accessed from the context parameter as ``ctx.sender()``, this
returns an address, which is either the address of an account or the address of
a smart contract instance::

   let sender = ctx.sender();

.. note::

   The **Send** action allows contract instances to interact with each other.

The owner can also be accessed through the context by using ``ctx.owner()``,
which will always return an account address, since only accounts can create and
own smart contract instances::

   let owner = ctx.owner();

Using the ``matches_account`` method on the sender address, we can compare it to
an account; the owner, and if the sender is a contract or not the owner account
it results in false, making ``ensure!`` reject the ``receive``-function
invocation::

   ensure!(sender.matches_account(&owner)); // Only the owner can increment.

There is also an optional third argument, which is the error to return
*when testing* the contract.
This error message will not be used in the resulting smart contract, when
deployed to the chain, since the protocol of the Concordium blockchain does not
log the error messages of smart contracts rejecting, therefore adding error
messages is only useful when testing.

.. note::

    If you want to reject directly in your smart contract, you should use
    ``bail!`` to terminate early. ``ensure_eq!`` and ``ensure!`` corresponds are
    using ``bail!`` internally. We strongly recommend using these for when the
    intention is to signal a logic error, or malformed input. ``panic!`` and
    equivalents should be reserved for unexpected error conditions. To reduce
    code size as much as possible we recommend using ``concordium_std::trap`` in
    place of ``panic!`` to reduce code size. There is no advantage in the
    unwinding logic that ``panic!`` provides, since this is not observable when
    the contract executes on the chain.

Now that we have ensured the context is right for incrementing the counter, we
just need to update the state::

   *state += 1;

Since increment does not create any actions on-chain, we just result in
**Accept**, which we can create using the ``accept`` function on the generic
``A``::

   Ok(A::accept())

Testing increment
=================

.. code-block:: rust

   #[test]
   fn test_increment() {
       // Setup
       let mut ctx = ReceiveContextTest::empty();
       let owner = AccountAddress([0u8; 32]);
       ctx.set_owner(owner);
       ctx.set_sender(Address::Account(owner));

       let amount = Amount::zero();

       let mut logger = LogRecorder::init();

       let mut state = 0;

       // Call the receive function
       let result : ReceiveResult<ActionsTree> = counter_increment(&ctx, &mut state);

       // Inspect the result
       let actions = match result {
           Ok(actions) => actions,
           Err(_) => fail!("Contract failed, when it should have succeeded."),
       };
       claim_eq!(actions, ActionsTree::Accept, "Contract should only accept");
       claim_eq!(state, 1, "The state should be incremented");
   }
