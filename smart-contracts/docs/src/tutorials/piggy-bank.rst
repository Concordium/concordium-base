.. highlight:: rust


.. _Rust: https://www.rust-lang.org/
.. _Serialize: https://docs.rs/concordium-std/latest/concordium_std/trait.Serialize.html
.. |Serialize| replace:: ``Serialize``
.. _concordium-std: https://docs.rs/concordium-std/latest/concordium_std/index.html
.. |concordium-std| replace:: ``concordium-std``
.. _`procedural macro for deriving`: https://docs.rs/concordium-std/latest/concordium_std/derive.Serialize.html
.. _init: https://docs.rs/concordium-std/latest/concordium_std/attr.init.html
.. |init| replace:: ``#[init]``
.. _receive: https://docs.rs/concordium-std/latest/concordium_std/attr.receive.html
.. |receive| replace:: ``#[receive]``


.. _piggy-bank:

==========
Piggy bank
==========

In this tutorial, we are going to build a minimal smart contract.
The goal is to give you a run-through every part of the contract development
process.
You will learn the basics of how to setup, write, build, test and deploy a
smart contract using the Rust_ programming language.

.. warning::

   The reader is assumed to have basic knowledge of what a blockchain and smart
   contract is, and some experience with Rust_.

.. contents:: Table of contents
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

We also need to setup a new smart contract project.
Follow the guide :ref:`setup-contract` and return to this point afterwards.

We are now ready for writing a smart contract for the Concordium blockchain!

Bringing in the standard library
================================

The source code of our smart contract is going to be in the ``src`` directory,
which already contains the file ``lib.rs``, assuming you follow the above guide
to setup your project.
Open ``src/lib.rs`` in your editor and you'll see some code for writing tests,
which you can delete for now. We will come back to tests later in this tutorial.

.. todo::

   Link the test section of this tutorial.

First, we bring everything from the |concordium-std|_ library into scope,
by adding the line::

   use concordium_std::*;

This library contains everything needed for writing our smart contract. It
provides convenient wrappers around some low-level operations making our code
more readable, and although it is not strictly necessary to use this, it will
save a lot of code for the vast majority of contract developers.

Piggy bank contract
===================

The contract we are going to build in this tutorial is going to act as a classic
piggy bank. Everyone should be able to insert money into it, but only the owner
can smash it and retrieve the money inside. Once the piggy bank have been
smashed, it should prevent insertion of money.

.. todo::

   Add image of piggy bank.

.. todo::

   Explain the life cycle of smart contracts

The piggy bank smart contract is going to contain a function for setting up a
new piggy bank and two functions for updating a piggy bank; one is for everyone
to use for inserting GTU, the other is for the owner to smash the piggy bank.

Specifying the state
====================

The piggy bank must contain some state. The blockchain keeps track of the
balance of each smart contract instance meaning the only state, we will need to
track is whether it have been smashed or not.

In Rust we represent this state as an enum, with a variant for the piggy bank
being intact and one for it being smashed::

   enum PiggyBankState {
      Intact,
      Smashed,
   }

On the blockchain, the state of a smart contract is represented by an array of
bytes, and it is important that our contract state is serializable to bytes.
When using the |concordium-std|_ library, this all boils down to our type
for the contract state having to implement the |Serialize|_ trait exposed by
|concordium-std|_.

Luckily the library already contains implementations for most of the primitives
and standard types in Rust_, and a `procedural macro for deriving`_
|Serialize|_ for most cases of enums and structs.

.. code-block::

   #[derive(Serialize)]
   enum PiggyBankState {
      Intact,
      Smashed,
   }

Setting up a piggy bank
=======================

Time to write the function for setting up a new piggy bank, which in turn means
specifying the ``init``-function for a smart contract.
A smart contract must specify an ``init``-function, which is called when new
instances of the contract are created, and is used to setup the initial state of
the contract instance.

.. note::

   If you have experience with Object-Oriented Programming, it might help to
   think of a smart contract as a *class*, the ``init``-function as a
   *constructor* and smart contract instances as *objects*.

In the case of the piggy bank; the initial state should be set to ``Intact``.


The ``#[init]`` macro
-------------------------

In Rust_ an ``init``-function can be specified as a regular function, annotated
with a procedural macro from |concordium-std| called |init|_.
With this we can define how to setup a piggy bank as::

   #[init(contract = "PiggyBank")]
   fn piggy_init(_ctx: &impl HasInitContext) -> InitResult<PiggyBankState> {
       Ok(PiggyBankState::Intact)
   }

The macro saves you from some details of setting up the function as an external
function, serializing the state to bytes and supplies a nicer interface for
accessing context information.

It requires a name for the smart contract, which we in this case choose to be
``"PiggyBank"``. The name is used as part of the exported function, and is how
we identify this smart contract, from any other smart contract in our smart
contract module.
::

   #[init(contract = "PiggyBank")]

The function it annotates only takes one argument ``ctx: &impl HasInitContext``,
which is a zero-sized struct with a number of getter functions for accessing
information about the current context, such as: who invoked this contract, any
supplied parameters and some information of the current state of the blockchain.

The return type of our function is ``InitResult<PiggyBankState>``, which is an
alias for ``Result<PiggyBankState, Reject>``. The returned state is serialized
and set as the initial state of the smart contract.
::

   fn piggy_init(_ctx: &impl HasInitContext) -> InitResult<PiggyBankState> {

Initializing our piggy bank state to be ``Intact`` is then straight forward::

   Ok(PiggyBankState::Intact)

A more complex smart contract would take a parameter, and check during
initialization that everything is set up as expected, but more about this
later.

Inserting money into a piggy bank
=================================

We have now defined how instances of our smart contract are created, and our
smart contract is in principle a valid contract at this point.
However, we would also like to define how to interact with instances of our
contract.
Specifically, a way to increment the counter, and recall the requirement of only
allowing the contract owner to increment.

A smart contract can expose zero or more functions for interacting with an
instance.
These functions are called ``receive``-functions, and can read and
write to the state of the instance, read the state of the blockchain and
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


The ``#[receive(...)]`` macro
=============================

Specifying ``receive``-functions in Rust, can be done using the procedural macro
|receive|_, which, like |init|_, sets up an external function and supplies us with
an interface for accessing the context. But, unlike the |init|_ macro, the
function for |receive|_ is also supplied with a mutable reference to the current
state of the instance.

