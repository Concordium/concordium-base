.. Should answer:
    - Why write a smart contract using rust?
    - What are the pieces needed to write a smart contract in rust?
        - State
            - Serialized
            - Schema
        - Init
        - Receive
    - What sort of testing is possible
    - Best practices?
        - Ensure 0 amount
        - Don't panic
        - Avoid heavy calculations

.. _writing-smart-contracts:

====================================
Developing smart contracts in Rust
====================================

On the concordium blockchain smart contracts are deployed as Wasm modules, but
Wasm is designed primarily as a compilation target and is not convenient for
writing by hand. Instead we can write our smart contract in the Rust_
programming language, which has good support for compiling to Wasm.

.. note:: We emphasize that there is no requirement that contracts must be
   written in Rust, this is simply the first SDK we provide. Manually written
   Wasm, or Wasm compiled from C, C++, AssemblyScript_, and others, is equally
   valid on the chain, as long as it adheres to the Wasm limitations we impose.

.. seealso::
    See :ref:`contract-module` for more about smart contract modules.

A smart contract module is developed in Rust as a library crate, which is then
compiled to Wasm. To obtain the correct exports the `crate-type` attribute must
be set to ``["cdylib", "rlib"]`` in the manifest file:

.. code-block::

    ...
    [lib]
    crate-type = ["cdylib", "rlib"]
    ...

Writing a smart contract using ``concordium_std``
=====================================================

It is recommended to use the ``concordium_std`` crate, which provides a
more Rust-like experience for developing smart contract modules and calling
host functions.

The crate allows to write ``init`` and ``receive``-functions as simple rust
functions annotated with ``#[init(...)]`` and ``#[receive(...)]`` respectively.

A simple counter example would look like:

.. code-block:: rust

    use concordium_std::*;

    type State = u32;

    #[init(contract = "counter")]
    fn counter_init(
        _ctx: &impl HasInitContext<()>,
        amount: Amount,
        _logger: &mut impl HasLogger,
    ) -> InitResult<State> {
        ensure_eq!(amount.micro_gtu, 0); // Amount must be 0
        let state = 0;
        Ok(state)
    }

    #[receive(contract = "counter", name = "increment")]
    fn contract_receive<A: HasActions>(
        ctx: &impl HasReceiveContext<()>,
        amount: Amount,
        _logger: &mut impl HasLogger,
        state: &mut State,
    ) -> ReceiveResult<A> {
        ensure_eq!(amount.micro_gtu, 0); // Amount must be 0
        ensure!(ctx.sender().matches_account(&ctx.owner()); // Only the owner can increment
        *state += 1;
        Ok(A::accept())
    }

There are a number of things to notice

- The type of the methods. The init methods must have the type as shown above,
  the only freedom the user has is in choosing what the state type is. The same
  applies to the receive method, with the additional requirement that the type
  of the ``state`` variable must match the type returned by the ``init`` method.

- The annotation ``#[init(contract = "counter")]`` marks the method it is
  applied to as the ``init`` method of the contract named ``counter``.
  Concretely this means that behind the scenes this macro generates an exported
  function with the required signature and name `init_counter`.

-  ``#[receive(contract = "counter", name = "increment")]`` deserializes and
   supplies the state to be manipulated directly. Behind the scenes this
   annotation also generates an exported function with name `counter.increment`
   that has the required signature, and does all of the boilerplate of
   deserializing the state into the required type ``State``.

.. note:: Note that deserialization is not without cost, and in some cases the
   user might want more fine-grained control over the use of host functions. For
   such use-cases the annotations support a ``low_level`` option, which has less
   overhead, but requires more from the user.

.. todo::
   Describe low-level


Serializable state and parameters
---------------------------------

On chain, the state of an instance is represented as a byte array, and exposed
in a similar interface as the ``File`` interface of the Rust standard library.

Using the default interface described in the preceding section, the type of the
contract state must be serializable in order for the generated code to be able
to construct the structured from the serialized one.

This can be done using the ``Serialize`` trait, which contains a functions for
both serializing and deserializing between values and their byte representation.

.. note::
   The ``Serialize`` interface does not support so-called zero-copy
   deserialization at the moment. This is coming as well, but it does make the
   interface more complex.

The ``concordium_std`` crate includes this trait and implementations for
most types in the Rust standard library. It also includes macros for deriving
the trait for user defined structs and enums.

.. code-block:: rust

    use concordium_std::*;

    #[derive(Serialize)]
    struct MyState {
        ...
    }

The same is necessary for parameters for ``init`` and ``receive``-functions.

.. note::

    Strictly speaking we only need to deserialize bytes to our parameter type,
    but it is convenient to be able to serialize types when writing unit tests.


Building a smart contract module with ``cargo-concordium``
==========================================================

The Rust compiler has good support for compiling to Wasm using the
``wasm32-unknown-unknown`` target. However even when compiling with
``--release`` the resulting build includes large sections of debug information
in custom sections, which are not useful for smart contracts on chain.

To optimize the build and allow for new features such as embedding schemas, we
recommend using ``cargo-concordium`` to build smart contract.

.. seealso::

    For instructions on how to build using ``cargo-concordium`` see
    :ref:`compile-module`.


Testing smart contracts
=======================

Unit tests with stubs
---------------------

Simulate contract calls
-----------------------

Best practices
==============

Don't panic
-----------

.. todo::
   Use trap instead.

Avoid creating black holes
--------------------------

.. todo::
   Contracts where funds cannot be recovered.

Move heavy calculations off-chain
---------------------------------


.. _Rust: https://www.rust-lang.org/
.. _Cargo: https://doc.rust-lang.org/cargo/
.. _AssemblyScript: https://github.com/AssemblyScript
