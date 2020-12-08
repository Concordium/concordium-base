.. _references-on-chain:

===================
References on-chain
===================

This is a reference of how modules and contract instances are referenced
*on-chain*.

Modules
=======

Modules are referenced via their *module reference*.
A reference for a module is simply its SHA256 hash.

Example of a module reference:

.. code-block:: console

   c840bd7f7e4b6d1dfc2fa0e3b84413d3cdfb5ef442efecae0e082a5808a614d9

.. note::

   If you hash a module, e.g., using `sha256sum`_, you will not get the same
   hash as is used on-chain.
   This is because on-chain modules are prepended with four additional bytes
   that describe which API-version of the Concordium tools they were built it.

Contract instances
==================

Contract instances are referenced via their *address*.
An address consists of an *index* and a *subindex*, both of which are
non-negative integers.

Example of a contract instance address:

.. code-block:: console

   {"index":0,"subindex":0}

Currently, only indexes are used.
Subindexes will be used when the deletion of instances has been implemented.
Until then, subindexes default to the value ``0``.

.. _sha256sum: https://linux.die.net/man/1/sha256sum
