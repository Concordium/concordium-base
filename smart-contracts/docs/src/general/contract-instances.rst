.. _contract-instances:

========================
Smart contract instances
========================

A **smart contract instance** is smart contract module together with a specific
state and amount of GTU tokens. Each instance thus by definition has its own
state and can hold GTU tokens. Multiple smart contract instances can be created
from the same module. For example, for the auction contract, there could be
multiple instances, each one dedicated to bidding for a specific item, with
their own participants.

Smart contract instances can be created from a deployed :ref:`smart contract
module<contract-module>` via the ``init`` transaction which invokes the
requested function in the *smart contract module*. This function can take a
parameter. Its end result is required to be the initial smart contract state of
the instance.

.. note::
    A smart contract instance is often just called an instance, when it is clear
    from the context it is a smart contract instance.

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

State of a smart contract instance
==================================

The state of a smart contract instance consists of two parts, the user-defined
state and the amount of GTU the contract holds. When referring to state we
typically mean only the user-defined state. The reason for treating the GTU
amount separately is that the GTU can only be spent and received according to
rules of the network, e.g., contracts cannot create new GTU, nor can they
destroy it.

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
of an array of bytes.

To summarize; the transaction includes:

- Reference to the smart contract module.
- Name of the ``init``-function.
- Parameter for the ``init``-function.
- Amount of GTU for the instance.

The ``init`` function can signal that it does not wish to create a new instance
with those parameters. If the ``init``-function accepts the parameters, it sets
up the initial state of the instance and its balance. The instance is given an
address on the chain and the account who send the transaction becomes the owner
of the instance. If the function rejects, no instance is created and only the
transaction for creating the instance is visible on chain.

.. seealso::
    See :ref:`initialize-contract` guide for how to do this.

Instance state
==============

Every smart contract instance holds its own state, which is represented on the
chain as an array of bytes.
The instance uses functions provided by the host environment to read, write and
resize the state.

.. seealso::
    See :ref:`host-functions-state` for the reference of these functions.

Smart contract state is limited in size. Currently the limit on smart contract
state is 16KiB.

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

.. _contract-instance-actions:

Logging events
==============

Each smart contract method execution, be it the ``init`` or ``receive`` function
can log events. These are designed for off-chain use, so that actors outside of
the chain can monitor for events and react on them. Logs are not accessible to
smart contracts, or any other actor on the chain. Events can be logged using a
function supplied by the host environment.

.. seealso::
    See :ref:`host-functions-log` for the reference of this function.

These event logs are retained by bakers and included in transaction summaries.

Logging an event has an associated cost, similar to the cost of writing to the
contract's state. In most cases it would only make sense to log a few bytes to
reduce cost.

Action description
------------------

A ``receive``-function returns a *description of actions*, to be be executed and
the host environment then attempts to execute these actions on the chain.

The possible actions a contract can produce are:

- **Accept** Do nothing, always succeeds.
- **Simple transfer** Send some amount of GTU from the balance of the instance
  to the specified account.
- **Send** Invoke ``receive``-function of the specified smart contract instance,
  and optioanlly transfer some GTU from the balance of the instance, to the
  receiving instance.

If the actions fail to execute, the ``receive``-function is reverted, leaving
the state and the balance of the instance unchanged. In such a case the only
visible artifacts are the transaction triggering ``receive``-function resulting
in a rejection, and payment for the execution.

Action descriptions can be combined to describe a sequence of actions to be
executed and have the second action to be executed depending on the first
action.

- **And** Try the second action **if** the first succeeds, otherwise fail.
- **Or** Try the second action **only if** the first action fails.

These combinators allow the action description to form a decision tree, where
the leafs are the actions and the nodes are combinators.

.. graphviz::
    :align: center
    :caption: Example of an action description, which tries to transfer to Alice
              and then Bob, if any of these fails, it will try to transfer to
              Charlie instead.

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

The whole actions tree is executed **atomically**, and either leads to updates
to all the relevant instances and accounts, or in case of rejection, to payment
for execution, but no other changes. The account which sent the initiating
transaction pays for execution of the entire tree.
