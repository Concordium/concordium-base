===============================================
My first smart contract
===============================================

In this tutorial, we are going to build a minimal smart contract.
The goal is to give you a run-through every part of the contract development
process.
You will learn the basics of how to setup, write, build, test and deploy a
smart contract using Rust.

This tutorial will *not* teach you Rust or focus how to build a complex smart
contract.

Introduction
============

We want to develop a smart contract using Rust, which is written as an ordinary
Rust library crate.
The library is then compile to Wasm using the Rust target
``wasm-unknown-unknown``.
Since it is just a Rust library, we can use Cargo_ for dependency management.

The contract we are going to build is a simple counter, the contract state is
just a number, which is initialized to 0 and the contract will have a function
for incrementing the state.

Installation
============
First step is to make sure the necessary tooling for building rust contracts is
installed.
The guide :ref:`setup_rust` will show you how to do this.
Also make sure to have your favorite text editor setup for Rust.

Create a contract project
=========================
To setup a new smart contract project, first create a project directory, inside
the project directory run the following in a terminal::

    cargo init --lib

This will setup a default Rust library project by creating a few files and
folders.
Your directory should now contain a ``Cargo.toml`` file and a ``src``
directory and some hidden files.

Next is to add ``concordium-sc-base`` as a dependency.
Which is a library for Rust containing procedural macros and functions for
writing small and efficient smart contracts.

You add the library by opening ``Cargo.toml`` and just below the line saying
``[dependencies]`` add a new line with ``concordium-sc-base = "1.0.0"``.

.. code-block::

    [dependencies]
    concordium-sc-base = "1.0.0"

.. note::
    Until the dependency is release on crates.io_, you will also have to clone
    the repo with ``concordium-sc-base`` and have the dependency to point at
    the directory instead, by adding the following to ``Cargo.toml``::

        [dependencies]
        concordium-sc-base = { path = "./path/to/concordium-sc-base" }

.. todo::
    Once the crate is released:

    - Verify the above is correct.
    - Remove the note.
    - Link crate documentation.

Writing a counter contract
==========================
We are now ready for writing the actual smart contract.
The source code of our smart contract is going to be in the ``src`` directory,
which already contains the file ``lib.rs``.
Open ``src/lib.rs`` in your editor and you'll see some code for writing tests.
We will use this later, so just leave it at the bottom, when we write the
contract.

First we bring everything
from the ``concordium-sc-base`` library into scope::

    use concordium_sc_base::*;


Contract state
--------------

Next we want to specify the type of the contract state. The contract state
could be any type, typically a struct or an enum, but since our contract is
going to be a simple counter, we just let the state be an integer::

    type State = u32;

``init``-function using the ``#[init(..)]`` macro
-------------------------------------------------

Every smart contract need an ``init``-function.
This function is called when new instances of the contract is created and will
typically setup the initial state of the contract.
Which in the case of the counter would be setting the state to 0.
Before going to much into the details of the ``init``-function in Rust, have a
look at the code::

    #[init(name = "counter")]
    fn counter_init<I: HasInitContext<()>, L: HasLogger>(
        _ctx: &I,
        _amount: Amount,
        _logger: &mut L,
    ) -> InitResult<State> {
        let state = 0;
        Ok(state)
    }

In Rust an ``init``-function can be specified as a regular function, annotated
with a procedural macro from ``concordium_sc_base`` called ``#[init(..)]``.
You are required to set the ``name`` attribute of the macro, which is going to
be the name of the exposed ``init``-function and therefore visible on the
chain.

Neither of the three parameters of the function are used our counter contract,
which by convention is written with a name starting with _.
Here is a brief description of what they are:

- **ctx**: An object with a bunch of getter functions for accessing information
  about the current context, such as who invoke this function and the state of
  the chain.
- **amount**: The amount of GTU included in the transaction which invoked this
  function.
- **logger**: An object with functions for outputting to the log of the smart
  contract.

The function return type is a ``InitResult<State>`` which is an alias for
``Result<State, Reject>``.

.. todo::
    Explain the return type, when the Reject type design is final.

The ``#[init(..)]`` macro save you from some low level details of setting up
the function as external and hides some call to host functions for setting the
state.

Understanding the actual body of our function is straight forward, as we just
returns the initial state of 0 wrapped in ``Ok``.

.. code-block:: rust

    use concordium_sc_base::*;

    type State = u32;

    #[init(name = "counter")]
    fn counter_init<I: HasInitContext<()>, L: HasLogger>(
        _ctx: &I,
        _amount: Amount,
        _logger: &mut L,
    ) -> InitResult<State> {
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
