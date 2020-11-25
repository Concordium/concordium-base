.. _local-simulate:

===================================
Locally simulate contract functions
===================================

This guide is about how to locally simulate an invocation of some ``init``- or
``receive``-function from a Wasm smart contract module in a given context and
state.
It is useful for inspecting a smart contract and the outcome of specific
scenarios.

.. seealso::

    For a guide on automated unit tests see :ref:`unit-test-contract`.

Preparation
===========

Make sure you have ``cargo-concordium`` installed, if not follow the guide
:ref:`setup-tools`.
You will also need a smart contract module in Wasm to simulate.

.. todo::
    Write the rest, when the schema stuff is in place

Simulating instantiation
========================

To simulate the instantiation of a smart contract instance using
``cargo-concordium``.

.. code-block:: sh

    cargo concordium run init --module contract.wasm \
                              --contract "my_contract" \
                              --context init-context.json \
                              --amount 12345 \
                              --parameter-bin parameter.bin \
                              --out-bin state.bin

``--context``: Here the ``init-context.json`` is a file containing context such
as the current state of the chain and the sender of the transaction and which
account invoked this function. An example of this context could be:

.. code-block:: json

    {
        "metadata": {
            "slotNumber": 1,
            "blockHeight": 1,
            "finalizedHeight": 1,
            "slotTime": 0
        },
        "initOrigin": "3uxeCZwa3SxbksPWHwXWxCsaPucZdzNaXsRbkztqUUYRo1MnvF"
    }


Simulating updates
==================

To simulate an update to a contract smart contract instance using
``cargo-concordium``.

.. code-block:: sh

    cargo concordium run update --module contract.wasm \
                                --contract "my_contract" \
                                --func "some_receive" \
                                --context receive-context.json \
                                --amount 12345 \
                                --parameter-bin parameter.bin \
                                --state-bin state-in.bin \
                                --out-bin state-out.bin

``--context``: Here the ``receive-context.json`` is a file containing context
such as the current state of the chain and the sender of the transaction, which
account invoked this function and which account or address is send the current
message.
An example of this context could be:

.. code-block:: json

    {
        "metadata": {
            "slotNumber": 1,
            "blockHeight": 1,
            "finalizedHeight": 1,
            "slotTime": 0
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

