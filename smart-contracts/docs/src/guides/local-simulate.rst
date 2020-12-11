.. _local-simulate:

===================================
Locally simulate contract functions
===================================

This guide is about how to locally simulate an invocation of some ``init``- or
``receive``-function from a Wasm smart contract module in a given context and
state.
This simulation is useful for inspecting a smart contract and the outcome in
specific scenarios.

.. seealso::

   For a guide on automated unit tests, see :ref:`unit-test-contract`.

Preparation
===========

Make sure you have ``cargo-concordium`` installed, if not follow the guide
:ref:`setup-tools`.
You will also need a smart contract module in Wasm to simulate.

.. todo::

   Write the rest, when the schema stuff is in place.

Simulating instantiation
========================

To simulate the instantiation of a smart contract instance using
``cargo-concordium``, run the following command:

.. code-block:: console

   $cargo concordium run init --module contract.wasm \
                               --contract "my_contract" \
                               --context init-context.json \
                               --amount 123456.789 \
                               --parameter-bin parameter.bin \
                               --out-bin state.bin

``init-context.json`` (used with the ``--context`` parameter) is a file that
contains context information such as the current state of the chain, the
sender of the transaction, and which account invoked this function.
An example of this context could be:

.. code-block:: json

   {
       "metadata": {
           "slotNumber": 1,
           "blockHeight": 1,
           "finalizedHeight": 1,
           "slotTime": "2021-01-01T00:00:01Z"
       },
       "initOrigin": "3uxeCZwa3SxbksPWHwXWxCsaPucZdzNaXsRbkztqUUYRo1MnvF"
   }

.. seealso::

   For a reference of the context see :ref:`simulate-context`.


Simulating updates
==================

To simulate an update to a contract smart contract instance using
``cargo-concordium``, run:

.. code-block:: console

   $cargo concordium run update --module contract.wasm \
                                 --contract "my_contract" \
                                 --func "some_receive" \
                                 --context receive-context.json \
                                 --amount 123456.789 \
                                 --parameter-bin parameter.bin \
                                 --state-bin state-in.bin \
                                 --out-bin state-out.bin

``receive-context.json`` (used with the ``--context`` parameter) is a file that
contains context information such as the current state of the chain, the
sender of the transaction, which account invoked this function, and which
account or address that sent the current message.
An example of this context could be:

.. code-block:: json

   {
       "metadata": {
           "slotNumber": 1,
           "blockHeight": 1,
           "finalizedHeight": 1,
           "slotTime": "2021-01-01T00:00:01Z"
       },
       "invoker": "3uxeCZwa3SxbksPWHwXWxCsaPucZdzNaXsRbkztqUUYRo1MnvF",
       "selfAddress": {"index": 0, "subindex": 0},
       "selfBalance": "0",
       "sender": {
           "type": "account",
           "address": "3uxeCZwa3SxbksPWHwXWxCsaPucZdzNaXsRbkztqUUYRo1MnvF"
       },
       "owner": "3uxeCZwa3SxbksPWHwXWxCsaPucZdzNaXsRbkztqUUYRo1MnvF"
   }

.. seealso::

   For a reference of the context see :ref:`simulate-context`.
