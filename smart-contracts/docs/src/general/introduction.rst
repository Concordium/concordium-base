.. Should answer:
    - What is a smart contract
    - Why use a smart contract
    - What are the use cases
    - What are not the use cases

.. _introduction:

====================================
Introduction to smart contracts
====================================

A smart contract is a user-supplied piece of code, used to define behavior that
is not directly available on the chain.
It can be used to define legal agreements and contracts, which are executed
automatically, as part of the blockchain protocol.

Smart contracts gain the same properties as the blockchain, which are
decentralization, transparency and trust.

What are smart contract for?
============================

The hope is to reduce the needed amount of trust in third-parties, in some cases
removing the need for trusted third-party, in other cases reducing their
capabilities and thus reducing the amount of trust needed in them.

A smart contract can receive, hold and send GTU, it is able to access the
current state of the blockchain and maintain its own state.
With these properties we can create smart contracts for managing Crowdfunding,
Auctions, Escrow contracts and many more.
It might help to imagine a smart contract as a bot, which imitates the behavior
of the trusted third-party.

Auction smart contract example
------------------------------

A use case for smart contracts could be for holding an auction; here we program
the smart contract to accept different bids from anyone and have it keep track
of the highest bidder.
When the auction is over, the smart contract sends back all the bids, which are
*not* the winner bid and sends the winner bid GTU to the seller, who sends the
item to the winner.
The smart contract replaces the main role of the auctioneer, the next problem is
to ensure the seller actually sends the item and there are various solutions for
this, which you can read about somewhere else.

Now we of course have to trust this bot instead, and since smart contract are
public on the blockchain, the behavior of the bot can be inspected and we can be
sure the smart contract cannot change.

What are smart contract *not* for?
----------------------------------

Smart contracts are a very exiting technology and people are still finding new
ways to take advantage of smart contracts.
However, there are some cases where smart contracts are not a great solution.

One of the key advantages of smart contracts are the trust in the code
execution, and to achieve this a large number of nodes in the blockchain network
have to execute the same code and ensure agreement of the result.
Naturally, this becomes expensive compared to running the same code on one node
in some cloud service.

In cases where a smart contract depends on heavy calculations, it might be
possible moving this calculation out of the smart contract and instead run it on
a single machine and use cryptographic tricks to ensure the result is correct.

Also, smart contracts have no privacy and everything the smart contract *knows*
is public on the blockchain, meaning it is difficult to handle sensitive data in
a smart contract, however possible in some cases again using cryptographic
tricks
