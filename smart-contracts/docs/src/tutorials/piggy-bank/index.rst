.. _Rust: https://www.rust-lang.org/


.. image:: piggy-bank.svg
   :width: 33%
   :align: center
   :alt: A Concordium piggy bank

.. _piggy-bank:

=============================
The piggy bank smart contract
=============================

.. todo::

   Link the repo with the code

In this tutorial, we are going to build a simple smart contract modelling a
piggy bank.
It should allow any account to insert GTU, and only the owner to smash it,
taking all of the GTU inside.

In the first part, you will learn how to write the very basic piggy bank smart
contract using the Rust_ programming language.

The second part is about how to test our piggy bank smart contract with unit
tests.

.. warning::

   The reader is assumed to have basic knowledge of what a blockchain and smart
   contracts are, and to have some experience with Rust_.

.. toctree::
   :maxdepth: 1
   :caption: Parts
   :numbered:

   writing
   testing
