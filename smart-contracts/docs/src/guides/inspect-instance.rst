.. _inspect-instance:

=================================
Inspect a smart contract instance
=================================

This guide will show you how to inspect a smart contract instance. Inspecting an
instance will show you a number of its attributes, including the state, owner,
and balance.

Preparation
===========

Make sure to have the latest ``concordium-client`` installed and a smart
contract instance on chain to inspect.

.. seealso::
    For instructions on how to install ``concordium-client`` see
    :ref:`setup-tools`.
    For how to deploy a smart contract module see :ref:`deploy-module` and for
    how to create an instance :ref:`initialize-contract`

Inspection
==========

To inspect, or show, information about a smart contract instance with the
address ``0``, run the following command:

.. code-block:: console

   $concordium-client show 0

The level of detail of an inspection depends on whether the ``show`` command has
access to a :ref:`contract schema <contract-schema>`. If it has access, it can
decode the state (which, otherwise, is shown in binary format using
hex-encoding). If the schema includes information about the parameters to
``receive``-functions, then this will also be displayed.
