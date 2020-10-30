===============================================
My first smart contract
===============================================

In this tutorial, we are going to build a minimal smart contract.
The goal is to give you a run-through every part of the contract development
process.
You will learn the basics of how to setup, write, build, test and deploy a
smart contract using Rust.

.. warning::
    This tutorial will *not* teach you programming in Rust.

Preparation
===========
Before we start; make sure you have the necessary tooling for building rust
contracts.
The guide :ref:`setup_rust` will show you how to do this.
Also make sure to have your favorite text editor setup for Rust.

We also need to setup a new smart contract project. Follow the guide
:ref:`setup_contract` and return to this point afterwards.

The source code of our smart contract is going to be in the ``src`` directory,
which already contains the file ``lib.rs``, assuming you follow the above guide
to setup your project.
Open ``src/lib.rs`` in your editor and you'll see some code for writing tests.
We will use this later, so just leave it at the bottom, when we write the
contract.

First we bring everything from the ``concordium-sc-base`` library into scope,
by adding the line::

    use concordium_sc_base::*;

Counter contract
============================

We are now ready for writing our first smart contract for the Concordium
blockchain.

The contract we are going to build in this tutorial is a gonna act as a
counter, which starts at 0 and exposes a function for incrementing.

The contract itself is not that interesting or even a realistic use case of
smart contracts, but it will be quick to understand and it enough for us to try
the whole process of contract development.

    *You must learn to crawl before you can walk*.


Specifying the contract state
-----------------------------

We want to specify the type of the contract state.
The contract state could be any type and is typically a struct or an enum.
Since our contract is going to be a simple counter, we just let the state
be an integer::

    type State = u32;

On the blockchain, smart contract state is represented by an array of bytes,
and it is important that our contract state is serializable to bytes.
When using the ``concordium-sc-base`` library, this all boils down to our type
for the contract state must implement the ``Serialized`` trait from
``concordium-sc-base``.

Luckily the library already contains implementations for most of the primitives
and standard types in Rust, meaning ``u32`` already implements the trait, so no
more work is necessary for the state.

.. todo:: Link to more information.

The ``init``-function
---------------------

A smart contract must specify an ``init``-function, which is called when new
instances of the contract are created.
It is typically used to setup the initial state of the contract instance and in
our case we want to set the counter state to 0.

Below you can see how we write the ``init``-function for our counter
contract, which we are about to explain in detail.

.. code-block:: rust

    #[init(name = "counter")]
    fn counter_init<I: HasInitContext<()>, L: HasLogger>(
        _ctx: &I,
        amount: Amount,
        _logger: &mut L,
    ) -> InitResult<State> {
        ensure_eq!(amount, 0, "The amount must be 0");
        let state = 0;
        Ok(state)
    }

``#[init(..)]`` macro
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In Rust an ``init``-function can be specified as a regular function, annotated
with a procedural macro from ``concordium_sc_base`` called ``#[init(..)]``.
The macro saves you from some details of setting up the function as
external function and supplies a nicer interface for accessing information and
logging.

You are required to set the ``name`` attribute of the macro, which is going to
be the name of the exposed ``init``-function and therefore visible on the
chain.
This also means that the contract name is limited to the possible names for a
function in Rust.
Unsurprisingly we choose to call our contract "counter".

Neither of the three parameters are used by our counter contract.
But here is a brief description of what they are:

- **ctx**: An object with a bunch of getter functions for accessing information
  about the current context, such as who invoke this function, the argument
  supplied and the state of the chain.
- **amount**: The amount of GTU included in the transaction which invoked this
  function.
- **logger**: An object with functions for outputting to the log of the smart
  contract.

The function return type is a ``InitResult<State>`` which is an alias for
``Result<State, Reject>``.

.. todo::
    Explain the return type, when the Reject type design is final.

The function body should set our counter state to 0, which is straight forward,
but first: since we are *not* using GTU in our contract, it is a good practice
to ensure that *no* amount of GTU is sent to an instance of this contract.

Avoiding black holes
-------------------------
As we are not going to specify a way to extract GTU from this contract, the
GTU send to an instance of the contract will be trapped.
It is surprisingly easy to create smart contracts, which acts as black holes
preventing the GTU send to them from being accessible *ever* again.

To prevent this, we let the contract instantiation fail, if some amount is
sent to it.
We do this with the ``ensure_eq!`` macro, which is given two arguments to
compare for equality, it *not* equal it will make the contract reject the
instantiation::

    ensure_eq!(amount, 0, "The amount must be 0");

The third argument is the error message to display *when testing* the contract.
This error message will not be included in the resulting smart contract, since
the protocol of the Concordium blockchain does not log the error messages of
smart contracts rejecting, therefore adding the error messages would be a waste
of bytes.

If you want to reject directly in your smart contract, you should use
``bail!``, which is the smart contract equivalent to ``panic!``, while
``ensure_eq!`` and ``ensure!`` corresponds to ``assert_eq!`` and ``assert!``
respectively, and are using ``bail!`` internally.
We strongly recommend using these over panicking and assertions, because they
give better error handling, easier to test, and produces smaller code in the
end as they take advantage of the ``Result`` type of our function.

Testing instantiation
------------------------
We now have enough to write our first unit test!




``receive``-functions
---------------------

.. code-block:: rust

    #[receive(name = "increment",)]
    fn contract_receive<R: HasReceiveContext<()>, L: HasLogger, A: HasActions>(
        ctx: &R,
        _amount: Amount,
        _logger: &mut L,
        state: &mut State,
    ) -> ReceiveResult<A> {
        ensure_eq!(amount, 0, "The amount must be 0");
        ensure!(ctx.sender().matches_account(&ctx.owner()), "Only the owner can increment.");
        *state += 1;
        Ok(A::accept())
    }



.. code-block:: rust

    use concordium_sc_base::*;

    type State = u32;

    #[init(name = "counter")]
    fn counter_init<I: HasInitContext<()>, L: HasLogger>(
        _ctx: &I,
        _amount: Amount,
        _logger: &mut L,
    ) -> InitResult<State> {
        ensure_eq!(amount, 0, "The amount must be 0");
        let state = 0;
        Ok(state)
    }

    #[receive(name = "increment",)]
    fn contract_receive<R: HasReceiveContext<()>, L: HasLogger, A: HasActions>(
        ctx: &R,
        _amount: Amount,
        _logger: &mut L,
        state: &mut State,
    ) -> ReceiveResult<A> {
        ensure_eq!(amount, 0, "The amount must be 0");
        ensure!(ctx.sender().matches_account(&ctx.owner()), "Only the owner can increment.");
        *state += 1;
        Ok(A::accept())
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn it_works() {
            assert_eq!(2 + 2, 4);
        }
    }

.. todo::
    Explain how to write a basic contract in ``src/lib.rs``

.. _Rust: https://www.rust-lang.org/
.. _Cargo: https://doc.rust-lang.org/cargo/
.. _rustup: https://rustup.rs/
.. _crates.io: https://crates.io/
