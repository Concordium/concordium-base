.. _local-settings:

==============
Local settings
==============

Local settings for ``concordium-client`` are stored in a single folder, the
location of which depends on the specific operating system used:

* Linux/MacOS: ``$HOME/.config/concordium``
* Windows: ``C:\Users\%USERNAME%\Documents\concordium-software``

The general structure of the folder is similar to the following:

.. code-block:: console

   concordium
   ├── accounts
   │   ├── names.map
   │   ├── <account1>
   │   │   ├── keypair0.json
   │   │   ├── keypair1.json
   │   │   ...
   │   │   └── encSecretKey.json
   │   ├── <account1>.threshold
   │   ├── <account2>
   │   │   ├── keypair0.json
   │   │   ├── keypair1.json
   │   │   ...
   │   │   └── encSecretKey.json
   │   └── <account2>.threshold
   └── contracts
       ├── contractNames.map
       └── moduleNames.map

.. todo::

   Should explanations of keypairs, encSecretKey, and thresholds also be added?


Local Names
===========

``concordium-client`` allows the user to add local aliases, or *names*, to
accounts, contract instances, and modules in order to make referencing them
easier.

Account Names
-------------

Account names are stored in the file ``accounts/names.map`` using a *custom*
format, and should look similar to the following:

.. code-block:: console

   my_account = 3XQ8fRKZM7bMK8YYEDgPLWDkCsKkk4YJkBwbtofBLUUnfwkbgv
   my_other_account = 4Lh8CPhbL2XEn55RMjKii2XCXngdAC7wRLL2CNjq33EG9TiWxj

Module Names
------------

Module names are stored in the file ``contracts/moduleNames.map`` as JSON, and
should look similar to the following:

.. code-block:: json

   {
       "my_module": "730b9e0a044e9e346de9fc431998668cfb94744f55485d4f89f0122b04f05894",
       "my_other_module": "c840bd7f7e4b6d1dfc2fa0e3b84413d3cdfb5ef442efecae0e082a5808a614d9"
   }


Contract Instance Names
-----------------------

Contract instance names are stored in the file ``contracts/contractNames.map``
as JSON, and should look similar to the following:

.. code-block:: json

   {
       "my_contract": {
           "index": 0,
           "subindex": 0
       },
       "my_other_contract": {
           "index": 1,
           "subindex": 0
       }
   }
