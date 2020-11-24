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
``cargo-concordium``,

.. code-block:: sh

    cargo concordium run init --source contract.wasm \
                              --contract "my_contract" \
                              --context init-context.json \
                              --amount 12345 \
                              --parameter-bin parameter.bin \
                              --out-bin state.bin

Simulating updates
==================


.. code-block:: sh

    cargo concordium run receive --source contract.wasm \
                                 --contract "my_contract" \
                                 --name "some_receive" \
                                 --context receive-context.json \
                                 --amount 12345 \
                                 --parameter-bin parameter.bin \
                                 --state-bin state-in.bin \
                                 --out-bin state-out.bin
