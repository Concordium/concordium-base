.. _contract-instances:

========================
Smart contract instances
========================

To use functionality provided by a smart contract, one must first create a
*smart contract instance* from a deployed :ref:`smart contract
module<contract-module>`.
The functionality is archive by interacting with this smart contract instance.

.. note::
    A smart contract instance is often just called an instance, when it is clear
    from the context it is a smart contract instance.

Multiple instances can be created for of a smart contract and each instance have
its own GTU balance and state.

.. graphviz::
    :align: center
    :caption: Example of smart contract module containing two smart contracts:
              Escrow and Crowdfunding. Each contract have two instances.

    digraph G {
        rankdir="BT"

        subgraph cluster_0 {
            label = "Module";
            labelloc=b;
            node [fillcolor=white, shape=note]
            "Crowdfunding";
            "Escrow";
        }

        subgraph cluster_1 {
            label = "Instances";
            style=dotted;
            node [shape=box, style=rounded]
            House;
            Car;
            Gadget;
            Boardgame;
        }

        House:n -> Escrow;
        Car:n -> Escrow;
        Gadget:n -> Crowdfunding;
        Boardgame:n -> Crowdfunding;
    }

Instantiating a smart contract on chain
=======================================

Every smart contract must contain a function for creating smart contract
instances, such a function is referred to as the ``init``-function.

To create a smart contract instance, an account sends a special transaction with
a reference to deployed smart contract module and the name of the
``init``-function to use for instantiation.

The transaction can also include an amount of GTU, which is added to the
balance of the smart contract instance.
An argument for the function is supplied as part of the transaction in the form
of a list of bytes.

To summaries; the transaction includes:

- Reference to smart contract module.
- Name of the ``init``-function.
- Parameter for ``init``-function.
- Amount of GTU for the instance.

If the ``init``-function is successful, it setups the initial state of the
instance and balance and the instance is given an address on the chain.
If the function rejects, no instance is created and only the transaction for
creating the instance is visible on chain.

.. seealso::
    See :ref:`initialize-contract` guide for how to do this.

Instance state
==============

Every smart contract instance holds its own state, which is represented on the
chain as a list of bytes.
The instance uses functions provided by the host environment to read, write and
resize the state.

.. seealso::
    See :ref:`host-functions-state` for the reference of these functions.

The size of the state is accounted for through the usage of *gas*.

.. todo::
    Check if the above about state account through gas is correct and add more.

.. seealso::
    Check out :ref:`resource-accounting` for more on this.

Interacting with an instance
============================

A smart contract can expose zero or more functions for interacting with an
instance.

.. note::
    Functions for interacting with a smart contract instance are referred to as
    ``receive``-functions.

Just like with ``init``-functions, the ``receive``-functions are triggered using
transactions, which contains some amount of GTU for the contract and an argument
for the function in the form of bytes.

To summaries; the transaction includes:

- Address to smart contract instance.
- Name of the ``receive``-function.
- Parameter for ``receive``-function.
- Amount of GTU for the instance.

Action description
------------------

A ``receive``-function returns a *description of actions*, to be be executed and
the host environment then attempts to execute these actions on the chain.

The possible actions a contract can produce are:

- **Accept** Do nothing, always succeeds.
- **Simple transfer** Send some amount of GTU from the balance of the instance 
  to some account.
- **Send** Invoke ``receive``-function of a smart contract instance.


If the actions fail to execute, the ``receive``-function is reverted, leaving
the state and the balance of the instance unchanged.
Only visible artifact is the transaction triggering ``receive``-function
resulting in a rejection.

Action descriptions can be combined to describe a sequence of actions to be
executed and have the second action to be executed depending on the first
action.

- **And** Try the second action if the first succeeds, otherwise fail.
- **Or** Try the second action *only* if the first action fails.

These combinators allow the action description to form a decision tree, where
the leafs are the actions and the nodes are combinators.

.. graphviz::
    :align: center
    :caption: Example of an action description, which tries to transfer to Alice
              and then Bob, if any of these fails, it will try to transfer to Charlie instead.

    digraph G {
        node [color=transparent]
        or1 [label = "Or"];
        and1 [label = "And"];
        transA [label = "Transfer x to Alice"];
        transB [label = "Transfer y to Bob"];
        transC [label = "Transfer z to Charlie"];

        or1 -> and1;
        and1 -> transA;
        and1 -> transB;
        or1 -> transC;
    }

.. seealso::
    See :ref:`host-functions-actions` for the reference of how to create the
    actions.
