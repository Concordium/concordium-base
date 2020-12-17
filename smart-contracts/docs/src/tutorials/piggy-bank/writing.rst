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
.. _HasActions: https://docs.rs/concordium-std/latest/concordium_std/trait.HasAction.html
.. |HasActions| replace:: ``HasActions``
.. _bail: https://docs.rs/concordium-std/latest/concordium_std/macro.bail.html
.. |bail| replace:: ``bail!``
.. _ensure: https://docs.rs/concordium-std/latest/concordium_std/macro.ensure.html
.. |ensure| replace:: ``ensure!``
.. _matches_account: https://docs.rs/concordium-std/latest/concordium_std/enum.Address.html#method.matches_account
.. |matches_account| replace:: ``matches_account``
.. _self_balance: https://docs.rs/concordium-std/latest/concordium_std/trait.HasReceiveContext.html#tymethod.self_balance
.. |self_balance| replace:: ``self_balance``

.. _piggy-bank-writing:

=====================================
Writing the piggy bank smart contract
=====================================

This is the first :ref:`part of a tutorial<piggy-bank>` on smart contract
development. In this part we will focus on how to write a smart contract in the
Rust_ programming language using the |concordium-std| library.

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
by adding the line:

.. code-block:: rust

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

The piggy bank smart contract is going to contain a function for setting up a
new piggy bank and two functions for updating a piggy bank; one is for everyone
to use for inserting GTU, the other is for the owner to smash the piggy bank.

Specifying the state
====================

The piggy bank must contain some state. The blockchain keeps track of the
balance of each smart contract instance meaning the only state, we will need to
track is whether it have been smashed or not.

In Rust we represent this state as an enum, with a variant for the piggy bank
being intact and one for it being smashed:

.. code-block:: rust

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
|Serialize|_ for most cases of enums and structs:

.. code-block:: rust

   #[derive(Serialize)]
   enum PiggyBankState {
       Intact,
       Smashed,
   }

We might as well derive ``Eq`` already, which is not necessary, but will come in
handy later:

.. code-block:: rust

   #[derive(Serialize, PartialEq, Eq)]
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
With this we can define how to setup a piggy bank as:

.. code-block:: rust

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

.. code-block:: rust

   #[init(contract = "PiggyBank")]

The function it annotates only takes one argument ``ctx: &impl HasInitContext``,
which is a zero-sized struct with a number of getter functions for accessing
information about the current context, such as: who invoked this contract, any
supplied parameters and some information of the current state of the blockchain.

The return type of our function is ``InitResult<PiggyBankState>``, which is an
alias for ``Result<PiggyBankState, Reject>``. The returned state is serialized
and set as the initial state of the smart contract.

.. code-block:: rust

   fn piggy_init(_ctx: &impl HasInitContext) -> InitResult<PiggyBankState> {

Initializing our piggy bank state to be ``Intact`` is then straight forward:

.. code-block:: rust

   Ok(PiggyBankState::Intact)

A more complex smart contract would take a parameter, and check during
initialization that everything is set up as expected, but more about this
later.

Define interaction with piggy banks
===================================

We have now defined how instances of our smart contract are created and the
smart contract is in principle a valid contract at this point.
However, we would also like to define how to interact with instances of our
contract.
Specifically how to insert GTU and how to smash a piggy bank.

A smart contract can expose zero or more functions for interacting with an
instance.
These functions are called ``receive``-functions, and can read and
write to the state of the instance, read the state of the blockchain and
return a description of actions to be executed on-chain.

.. note::

   A continuation of the analogy to Object Oriented Programming:
   ``receive``-functions corresponds to object methods.

The ``#[receive(...)]`` macro
-----------------------------

Specifying ``receive``-functions in Rust, can be done using the procedural macro
|receive|_, which, like |init|_, is used to annotate a function and sets up an
external function and supplies us with an interface for accessing the context.
But, unlike the |init|_ macro, the function for |receive|_ is also supplied with
a mutable reference to the current state of the instance:

.. code-block:: rust

   #[receive(contract = "MyContract", name = "some_interaction")]
   fn some_receive<A: HasActions>(
       ctx: &impl HasReceiveContext,
       state: &mut MyContractState,
   ) -> ReceiveResult<A> {
      ...
   }

The macro requires the name of the contract given using the ``contract``
attribute, which should match the name in the corresponding attribute in |init|_
(``"PiggyBank"`` in our case). It also requires a name to identify this
particular ``receive``-function using ``name``, this name together with the
contract name have to be unique for a smart contract module.

The return type of the function is ``ReceiveResult<A>``, which is an alias for
``Result<A, Reject>``.
Here ``A`` implements |HasActions|, which exposes functions for creating the
different actions.

.. rubric:: Actions

A smart contract can produce 3 types of actions:

- **Accept**: Accept incoming GTU. Always succeeds.
- **Simple Transfer**: Transfer some amount of GTU from the balance of the
  smart contract instance to an account.
- **Send**: Trigger ``receive``-function of a smart contract instance, with
  a parameter and an amount of GTU.

Also there are two ways to sequence these actions:

- **And**: Runs the first action, if it succeeds runs the second action,
  otherwise results in rejection.
- **Or**: Runs the first action, **if it fails**, runs the second action,
  otherwise results in success.

In this contract we will only need to use **Accept** and **Simple Transfer**.

Inserting money
---------------

The first interaction we will specify for our piggy bank, is how to insert GTU.
We start with defining a ``receive``-function as:

.. code-block:: rust

   #[receive(contract = "PiggyBank", name = "insert")]
   fn piggy_insert<A: HasActions>(
       _ctx: &impl HasReceiveContext,
       state: &mut PiggyBankState,
   ) -> ReceiveResult<A> {

   }

Here we make sure the contract name matches the one we use for the |init|_ macro
and we name this ``receive``-function ``"insert"``.

In the function body, we have to make sure the piggy bank is still intact, the
smart contract should reject any calls trying to call insert if the piggy bank
was smashed:

.. code-block:: rust

   if *state == PiggyBankState::Intact {
      return Err(Reject {});
   }

Since returning early is a common pattern when writing smart contracts and in
Rust_ in general, |concordium-std| exposes a |bail|_ macro:

.. code-block:: rust

   if *state == PiggyBankState::Intact {
      bail!();
   }

Checking a bunch of conditions and returning early is also a common pattern, so
there is even a |ensure|_ macro for this, it takes a condition and returns
early, if this is not true:

.. code-block:: rust

   ensure!(*state == PiggyBankState::Intact);

From this line, we will know that the state of the piggy bank is intact and all
we have left to do is accept the incoming amount of GTU.
The GTU balance is maintained by the blockchain, so there is no need for us to
maintain this in our contract, it just needs to produce the accept action, which
is possible using the generic ``A`` by running ``A::accept()``, which you will
hear more about in a moment.

.. code-block:: rust

   Ok(A::accept())

So far we have the following definition of how to insert in a piggy bank:

.. code-block:: rust

   #[receive(contract = "PiggyBank", name = "insert")]
   fn piggy_insert<A: HasActions>(
       _ctx: &impl HasReceiveContext,
       state: &mut PiggyBankState,
   ) -> ReceiveResult<A> {
       ensure!(*state == PiggyBankState::Intact);
       Ok(A::accept())
   }

Our definition is almost of how to insert GTU is almost done, but one important
detail is missing.
If we were to send some amount of GTU to the current definition, it would reject
before even running our code. This is a safety feature of |concordium-std|,
which assumes by default that function defined using |init| and |receive| are
not to accept any non-zero amount of GTU.

The reason for this behavior; is to reduce the risk of creating a smart
contract accepting GTU without functionality for retrieving the GTU of the
smart contract. A smart contract without a way to extract GTU, should be sure
not to accept any non-zero amount of GTU, since these GTU would be lost
forever.

Our piggy bank is gonna have a way to retrieve GTU, so we can disable this by
adding the ``payable`` attribute to the |receive| macro, which will allow the
function to accept a non-zero amount of GTU. Now the function is required to
take an extra argument ``amount: Amount``, which represents the amount included
in the current transfer triggering this function of the smart contract.

.. note::

   The ``payable`` attribute also exists for the |init| macro.

.. code-block::
   :emphasize-lines: 1, 4

   #[receive(contract = "PiggyBank", name = "insert", payable)]
   fn piggy_insert<A: HasActions>(
       _ctx: &impl HasReceiveContext,
       _amount: Amount,
       state: &mut PiggyBankState,
   ) -> ReceiveResult<A> {
       ensure!(*state == PiggyBankState::Intact);
       Ok(A::accept())
   }

Again, since the blockchain is maintaining the balance of our smart contract, we
do not have to, and the ``amount`` is not used by our contract.

Smashing a piggy bank
---------------------

Now that we can insert GTU into a piggy bank, we are only left to define how to
smash one.
Just to recap, we only want the owner of the piggy bank (smart contract
instance) to be able to call this and only if the piggy bank has not already
been smashed.
It should set its state to be smashed and transfer all of its GTU to the owner.

Again we use the |receive|_ macro, and start with:

.. code-block:: rust

   #[receive(contract = "PiggyBank", name = "smash")]
   fn piggy_smash<A: HasActions>(
       ctx: &impl HasReceiveContext,
       state: &mut PiggyBankState,
   ) -> ReceiveResult<A> {

   }

We ensure the contract name matches the one of our smart contract, and we choose
to name this function ``"smash"``.
Since the owner is about to empty the piggy bank, it would not make sense to
allow a non-zero amount, meaning we do not add the ``payable`` attribute here.

To access the contract owner, we use a getter function exposed by the context
``ctx``:

.. code-block:: rust

   let owner = ctx.owner();

This returns the account address of the contract instance owner, i.e. the
account which created the smart contract instance by invoking the
``init``-function.

Similarly the context have a getter function for the one who send the current
message, which triggered this ``receive``-function:

.. code-block:: rust

   let sender = ctx.sender();

Since smart contract instances are capable of sending messages as well as
accounts, ``sender`` is of the  ``Address`` type, which is either an account
address or a contract instance address.

To compare the ``sender`` with ``owner`` we can use the |matches_account|_
method defined on the ``sender``, which will only return true if the sender is
an account address and is equal to the owner:

.. code-block:: rust

   ensure!(sender.matches_account(&owner));

Next we ensure the state of the piggy bank is ``Intact``, just like previously:

.. code-block:: rust

   ensure!(*state == PiggyBankState::Intact);

At this point we know, the piggy bank is still intact and the sender is the
owner, meaning we now get to the smashing part:

.. code-block:: rust

   *state = PiggyBankState::Smashed

Since the state is a mutable reference, we can simply mutate it to be
``Smashed``, preventing anyone from inserting any more GTU.

Lastly we need to transfer the amount of GTU on the balance of our current piggy
bank (smart contract instance).

To transfer some amount of GTU from a smart contract instance, we create an
action for a simple transfer, again using the generic ``A``.
To construct a simple transfer, we need to provide the address of the receiving
account and the amount to include in the transfer.
In our case the receiver is the owner of the piggy bank and the amount is the
entire balance of the piggy bank.

The context have a getter function for reading
the current balance of the smart contract instance, which is called
|self_balance|_:

.. code-block:: rust

   let balance = ctx.self_balance();

And since we have already have the owner address, we just need to result in the
the simple transfer action:

.. code-block:: rust

   Ok(A::simple_transfer(&owner, balance))

The final definition of our "smash" ``receive``-function is then:

.. code-block:: rust

   #[receive(contract = "PiggyBank", name = "smash")]
   fn piggy_smash<A: HasActions>(
       ctx: &impl HasReceiveContext,
       state: &mut PiggyBankState,
   ) -> ReceiveResult<A> {
       let owner = ctx.owner();
       let sender = ctx.sender();
       ensure!(sender.matches_account(&owner));
       ensure!(*state == PiggyBankState::Intact);

       *state = PiggyBankState::Smashed;

       let balance = ctx.self_balance();
       Ok(A::simple_transfer(&owner, balance))
   }

.. note::

   Since a blockchain is a decentralized system, one might think we have to
   worry about the usual problems, when dealing with mutable state. Problems
   such as race conditions, but the semantics of smart contracts require the
   execution to be atomically, in order to reach consensus.

We now have all the parts for our piggy bank smart contract, before we move on
to testing it, we check that it builds by running:

.. code-block:: console

   $cargo concordium build

Which should succeed if everything is setup correctly, otherwise compare your
code with the one found here.

.. todo::

   Link the final code again.
