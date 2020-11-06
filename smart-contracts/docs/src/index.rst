.. Concordium smart contracts documentation master file, created by
   sphinx-quickstart on Thu Oct 22 15:01:04 2020.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

====================================================================
Concordium Smart Contract Documentation!
====================================================================

Welcome to the official documentation of Concordium smart contracts!

The documentation is split into four categories

   - **General**: Explaining concepts and details for understanding concordium
     smart contracts.
   - **Tutorials**: Step by step walkthrough with details explained as needed.
   - **How-to guides**: Short guides to achieve specific goals.
   - **References**: Precise descriptions of the machinery.


.. todo::
   Describe the structure of the documentation

.. todo::
   A list of information, still missing from the documentation

   - Resource accounting and limiting contracts (Energy)
   - Full description of a smart contract structure
   - Deployment
   - Queries
   - Cargo-concordium reference
   - Contract examples
   - Contract best practices (ensure amount is 0 ...)
   - Description of contract schema
   - Logging in a contract

.. toctree::
   :maxdepth: 1
   :caption: General

   general/introduction
   general/contract-on-chain
   general/develop-contracts

.. toctree::
   :maxdepth: 1
   :caption: Tutorials

   tutorials/first-contract

.. toctree::
   :maxdepth: 1
   :caption: How-to guides

   guides/setup-tools
   guides/setup-contract
   guides/unittest-contract
   guides/local-simulate
   guides/build-schema
   guides/deploy-module
   guides/initialize-contract
   guides/interacting-instance
   guides/interact-on-chain/index

.. toctree::
   :maxdepth: 1
   :caption: References

   references/host-fns
   concordium-sc-base (crate docs) <https://crates.io/crates/concordium-sc-base>


.. Indices and tables
.. ==================

.. * :ref:`genindex`
.. * :ref:`modindex`
.. * :ref:`search`

.. todolist::
