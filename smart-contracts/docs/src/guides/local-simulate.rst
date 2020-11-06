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

    For a guide on automated unit tests see :ref:`unittest-contract`.

Make sure you have ``cargo-concordium`` installed, if not follow the guide
:ref:`setup-tools`.
You will also need a smart contract module in Wasm to simulate.

.. todo::
    Write the rest, when the schema stuff is in place


.. code-block:: sh

    cargo concordium run init --source contract.wasm \
                              --name "some_init" \
                              --context init-context.json \
                              --amount 123 \
                              --parameter parameter.bin \
                              --out state.bin


.. code-block:: sh

    cargo concordium run receive --source contract.wasm \
                                 --name "some_receive" \
                                 --context receive-context.json \
                                 --amount 123 \
                                 --parameter parameter.bin \
                                 --state state-in.bin \
                                 --out state-out.bin
