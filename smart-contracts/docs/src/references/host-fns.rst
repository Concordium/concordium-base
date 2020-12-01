.. _host-functions:

================================
Contract host functions
================================
This is a reference of the functions in the ``concordium`` module supplied by a
host running smart contract Wasm module.

.. warning::
    These functions are not meant to be called directly by smart contract writers.
    Instead used behind a more idiomatic language-specific API supplied by a
    library, such as ``concordium-std`` for Rust.

    .. todo::
        Link ``concordium-std`` documentation.

.. module:: concordium

.. _host-functions-log:

Logging events
================================

.. function:: log_event(start, length)

    Adds a log item from an array of bytes.
    If not enough data can be read then this function will trap and abort
    execution of the smart contract.

    :param i32 start: Pointer to start of the item in linear memory.
    :param i32 length: Number of bytes in the item.

Function parameter
================================

.. function:: get_parameter_size() -> i32

    Get the byte size of the parameter.

    :return: byte size of the parameter
    :rtype: i32

.. function:: get_parameter_section(location, length, offset) -> i32

    Read a section of the parameter to the given location.
    Return the number of bytes read.
    The location is assumed to contain enough memory to write the requested
    length into.

    :param i32 location: Pointer (in Wasm linear memory) of the write location.
    :param i32 length: Number of bytes to read from the parameter.
    :param i32 offset: Starting offset in the parameter bytes.
    :return: The number of actual bytes read. This is always less than or equal
             to ``offset``, but could be less if the parameter does not have
             enough bytes available.
    :rtype: i32

.. _host-functions-state:

Smart contract instance state
=================================================

.. function:: state_size() -> i32

    Get the byte size of the contract state.

    :return: byte size of the contract state
    :rtype: i32

.. function:: load_state(location, length, offset) -> i32

    Read a section of the state to the given location. Return the number of
    bytes written. The location is assumed to contain enough memory to write the
    requested length into. If not, the function will trap and abort execution of
    the contract.

    :param i32 location: Pointer to write location.
    :param i32 length: Number of bytes to read
    :param i32 offset: Starting offset in the bytes
    :return: The number of read bytes
    :rtype: i32

.. function:: write_state(location, length, offset) -> i32

    Write a section of the state to the given location.
    Return the number of bytes written.
    The location is assumed to contain enough memory to write the requested
    length into.

    :param i32 location: Pointer to read location
    :param i32 length: Number of bytes to write
    :param i32 offset: Starting offset in the bytes
    :return: The number of written bytes
    :rtype: i32


.. function:: resize_state(new_size) -> i32

    Resize state to the new value (truncate if new size is smaller).
    The additional state is initialized to `0`.

    :param i32 new_size: New size of contract state in bytes.
    :return: 0 if this was unsuccessful (new state too big), or 1 if successful
    :rtype: i32

.. _host_function_chain_getters:

Chain data
================================
Functions for reading information about the chain.

.. function:: get_slot_time() -> i64

    Get time in milliseconds at the beginning of this block.

    :return: Time in milliseconds
    :rtype: i64

.. function:: get_slot_number() -> i64

    Get the slot number of the current block.

    :return: Slot number
    :rtype: i64

.. function:: get_block_height() -> i64

    Get block height of the current block.

    :return: Block height
    :rtype: i64

.. function:: get_finalized_height() -> i64

    Get the height of the last finalized block, i.e., block to which the
    current block has a finalized pointer to.

    :return: Finalized height
    :rtype: i64


Only in ``init``-function
================================
Functions only accessible for smart contract ``init``-functions. If called from
a ``receive`` function execution will abort.

.. function:: get_init_origin(start)

    Get the address of the account that triggered the ``init``-function.

    :param i32 start: Pointer of location to put the address. The address is 32
                      bytes and the memory must be large enough to contain it.


Only in ``receive``-function
================================
Functions only accessible for smart contract ``receive``-functions.

.. function:: get_receive_invoker(start)

    Get the address of the account that initiated the top-level transaction
    which lead to triggering the ``receive``-function.

    :param i32 start: Pointer of location to put the address

.. function:: get_receive_sender(start)

    Get the address of the account or contract, triggering the ``receive``-function.

    :param i32 start: Pointer of location to put the address

.. function:: get_receive_self_address(start)

    Get the address of the contract instance, running the ``receive``-function.

    :param i32 start: Pointer of location to put the address

.. function:: get_receive_owner(start)

    Get the address of the account, which created the contract instance.

    :param i32 start: Pointer of location to put the address

.. function:: get_receive_self_balance() -> i64

    Get the current balance of the contract instance.

    :return: Current balance of the contract instance
    :rtype: i64

.. _host-functions-actions:

Action description
--------------------------------
The description of actions to execute on the chain, returned by smart contract
``receive``-function.

.. function:: accept() -> i32

    Constructs a accept action, indicating the function was successful.

    :return: Identifier of the resulting action.
    :rtype: i32

.. function:: simple_transfer(addr_bytes, amount) -> i32

    Constructs a simple transfer of GTU action.

    :param i32 addr_bytes: Pointer to the address of the receiver
    :param i64 amount: The amount of GTU to send
    :return: Identifier of the resulting action.
    :rtype: i32

.. function:: send(addr_index, addr_subindex, receive_name, receive_name_len, amount, parameter, parameter_len) -> i32

    Constructs an action for sending a message to another smart contract instance.

    :param i64 addr_index: Index of the smart contract instance address to send to
    :param i64 addr_subindex: Subindex of the smart contract instance address to send to
    :param i32 receive_name: Pointer to a memory location containing the name of the ``receive``-function to invoke
    :param i32 receive_name_len: Length of the receive method name. Determines how much memory will be read by the host.
    :param i64 amount: The amount of GTU to invoke the receive method with
    :param i32 parameter: Pointer to a memory location containing the parameters to the ``receive``-function
    :param i32 parameter_len: Length of the parameters
    :return: Identifier of the resulting action.
    :rtype: i32

.. function:: combine_and(first, second) -> i32

    Combine two actions using ``and``.
    Only run the second if the first succeeds.
    If the given identifiers are not valid, i.e., returned by a previous call to
    one of the ``actions`` functions, this function will abort.

    :param i32 first: Identifier of the first action.
    :param i32 second: Identifier of the second action.
    :return: Identifier of the resulting action.
    :rtype: i32

.. function:: combine_or(first, second) -> i32

    Combine two actions using ``or``.
    Only runs the second of the first fails.
    If the given identifiers are not valid, i.e., returned by a previous call to
    one of the ``actions`` functions, this function will abort.

    :param i32 first: Identifier of the first action.
    :param i32 second: Identifier of the second action.
    :return: Identifier of the resulting action.
    :rtype: i32


