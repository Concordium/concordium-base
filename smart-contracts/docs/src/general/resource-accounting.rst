
.. _resource-accounting:

===================
Resource accounting
===================

.. danger::
    Precise definitions of cost accounting is still being worked out and this
    page is therefore incomplete and the information will possibly change.

Cost accounting
===============

In this chapter, we describe how we account for execution cost. The goal is to
be able to run a function with an objective limit on conceptual execution cost
where execution will abort when the limit is reached. In a deterministic
environment / with only deterministic instructions, executing the same function
with the same limit should result in the same state. Costs are defined in terms
of resource usage, e.g. execution time.

In addition to limiting total resource usage with a cost limit, we also want to
set individual limits for some resources, e.g. the maximum memory allocated for
executing a function.

.. note::
   * This chapter does not cover the following aspects of costs that will also
     be relevant:

     * Processing of modules, e.g. decoding, validation, compilation and
       performing the source code transformation described here * Execution cost
       of the accounting itself
     * Execution cost of the additional host functions
       we provide

   * The cost specification currently leaves open the concrete factors between
     different costs. These have to be determined experimentally. However, the
     costs for most instructions are based on a few basic costs.


Approach
--------

To implement cost accounting, we first have to define a measure of execution
cost. To this end, we assign each instruction a natural number of abstract unit
that represents its execution cost. For defining costs that approximately mirror
actual execution costs (e.g. execution time), we argue on the level of a
conceptual stack machine which we describe up to the required detail in the next
section.

Second, we need a way of counting cost during execution. There are two basic
ways of doing so:

* Modifying an interpreter / runtime system to account for each instruction's
  cost before executing it.
* A source code transformation that inserts accounting
  instructions which update a global variable representing the cost budget. Thus
  the WebAssembly program accounts for its execution on its own.

The latter has the advantage that one can use an existing interpreter without
modifications, whereas the former might be more efficient.

We choose an intermediate approach: We do a source code transformation that
inserts accounting instructions, but these are only calls to host functions
which do the actual accounting on the host side (e.g. at the level of the
interpreter). As host functions are a standard feature of WebAssembly, existing
interpreters can still be used, but the host functions have to be implemented in
the interpreter's environment. As a result, the implementation is less flexible
but easier and probably more efficient.

Note that host function calls and cost calculation are not for free, so their
own cost should probably be considered when calculating cost. To this end, a
suitable constant could be added to each cost. As most costs are known
statically, this does not incur additional execution cost in most cases.


Assumptions on implementations
------------------------------

We make some basic assumptions on an interpreter or runtime system executing a
function. This is relevant for the conceptual costs we assume for different
operations. To not having to make too strong assumption that might restrict the
possible implementations too much,  we have to be more conservative in some
cases, e.g. assuming a linear cost where implementations might only have a
constant cost. This might even be the case for two different operations, where
any reasonable implementation would in at least one of the two have an actual
cost that is lower not just by a constant factor.

While with these assumptions we might not get the most accurate cost accounting,
we can more easily reach the goals of a first version, i.e. a cost specification
that is simple, rather implementation independent and likely "correct up to
constant factors".

Code representation
^^^^^^^^^^^^^^^^^^^

The code consists of a linear sequence of numbered instructions which can
contain references to other positions in this sequence. Note that the positions
of instructions referred to by labels that are targeted by branching
instructions are known statically.

We assume an instruction pointer that refers to the current position in the
instruction sequence and that is incremented after the execution of each
instruction. Moving the instruction pointer in the sequence by any offset is
assumed to have constant and cheap cost.

Stacks
^^^^^^

We assume that execution uses two conceptual stacks.

* The **frame stack** holds function execution frames.
* The **operand stack** holds values consumed and produced by instructions.

Note that a label stack as used in the specification of the semantics is not
necessary, as its state at each instruction is known statically. Instead, we
assume that branching instructions encode directly the code positions to jump
to, and necessary relative positions on the operand stack.

An actual implementation might combine some of these stacks, however, it is
important that the conceptual stacks can be accessed individually and there is
no implicit cost of moving data between the stacks than that we explicitly
mention.

In general we assume that indexing, reading and writing from stacks is rather
cheap. To ensure this, we will impose limits on the size of these stacks, so
that it is reasonable to assume that these stacks are indeed fast to access,
e.g. because one can assume that the data resides in a fast cache.


Frame stack
~~~~~~~~~~~
A function execution frame contains:

* The function's local variables, i.e., its arguments plus the defined locals

* Some small and constant-sized administrative information, like the instruction
  pointer from where the function was called, the position of the previous frame
  on the stack and/or the current position on the operand stack when entering
  the function.

The size of an entry on the frame stack is thus variable. It depends at least on
the number of locals, and also on the current operand stack height should the
operand stack be part of the frame (but note that the maximum stack height
during the execution of a function is known statically). As the stack only needs
to be accessed from the top (it is only possible to access the locals and
operands and to return from the current function), we can assume that accessing
operands and removing a frame are cheap constant-time operations.

Operand stack
~~~~~~~~~~~~~

The operand stack holds the operands consumed and produced by the instructions
of the current function. Operands are values of the two supported types (|I32|
and |I64|; we disallow |F32| and |F64|).

Technically the operand stack could either be part of the current function frame
on the frame stack or be a separate stack, containing all current values on the
conceptual stack (not just those of the current function), as it is the case in
the specification of the semantics. In the latter variant, some copying of
argument/return values can be avoided (by function locals being on the operand
stack, beginning with the already residing arguments) but we do not want to make
these assumptions and therefore it should not really matter which way the
implementation chooses. In any case we assume that the operand stack is cheap
memory, as we do for the frame stack.

Even though there are 32 and 64 bit values, we assume that each entry on the
stack uses the same width (bit size), so that indexing is cheap. Note that for a
stack with variable-width entries constant (but still with considerable cost)
access and modification operations can be implemented by e.g. maintaining an
additional mapping of indices to offsets.

A note on the operand stacks and anonymous registers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Note that the WebAssembly specification states that an operand stack is
technically not necessary as by validation the maximum stack height is known
statically and thus the stack can be viewed as a set of anonymous registers (see
:ref:`Concepts <instruction>`). However, this of course only refers to the
operand stack of the *current frame* - as there (theoretically) can be an
unbounded number of frames, there can also be an unbounded number of operands on
the (single) conceptual operand stack; and a practical limit on call stack
height would not result in a practical limit for registers. Using registers
instead of an operand stack only for the current frame should be possible, but
note the following consequences:

* When entering a new frame, the current frame's registers have to be stored
  (probably in its frame). When leaving a frame, the previous frame's registers
  have to be restored and results from the current function have to be put into
  the respective registers according to the previous frame. Details depend on
  the calling convention.

* A simple implementation using an operand stack can just execute all
  instructions and put their results on the operand stack, including results
  that cannot be used (consider a loop of type :math:`[\I32] \to [\I32~\I32]`
  that consumes a counter and produces a constant and the decremented counter;
  each iteration adds another constant to the operand stack, but -- due to
  validation -- only the counter at the top can be accessed by the loop and only
  the counter and last constant added can be accessed by the instructions after
  the loop). A register-based implementation must instead overwrite inaccessible
  values (this corresponds to cleanup on branching that we actually assume the
  stack-based implementation to do, see below).

* Some instructions will have different behaviour; in addition to the points
  mentioned above, e.g. the :math:`\DROP` instruction will probably become a
  nop.

* There remains the problem that even though a function's operand stack height
  is statically known, there is no restriction on this height, and it cannot be
  assumed that an executing machine provides as many registers. It is unclear
  whether limiting each function's operand stack height such that the required
  number of registers can be assumed is feasible, especially w.r.t. the Wasm
  code compilers produce.

All in all, we could let the cost specification assume a register-based
implementation, but would probably have to assume that in some cases registers
are actually represented by memory (though most probably cached), and thus
assume a respective higher cost. It is also possible to assume higher cost only
when a certain maximum stack height is exceeded (the cost can still be
determined statically). The remaining parts regarding cost should be quite
similar to having an operand stack.

.. Wrong: actually be simpler in comparison to having an operand stack, e.g.
.. regarding handling of inaccessible values.

Operand stack cleanup (or register organization)
------------------------------------------------

Note that in both, stack-based and register-based implementation, cleanup after
branching is necessary in certain cases. For example, a block with a
:math:`\BRIF` could be left with different operand stack heights depending on
whether the branch is taken or not (the instructions before the branch might
produce a higher stack than specified by the return type, so that if the branch
is taken, these values must be discarded; but if the branch is not taken, the
following instructions may actually use these values). In the stack-based model
we have to remove additional values produced by the block beneath the result
values (as the original values beneath the block arguments are assumed there).
In the register-based model, the results can be in different registers (each
stack position corresponds to a register) and thus have to be moved to the
expected registers as given by the block's type (e.g., if a block with type
:math:`[\I32] \to [\I32~\I32]` is entered with a stack height of :math:`4`, the
results are expected at stack heights (or registers) :math:`4` and :math:`5`).
Therefore the cost specification assumes a cost for cleanup in the form of
copying the result values of a block to a new place. See :ref:`cost for br l
<cost-br>` for details.

..
   However, for generality (processors only provide a limited amount of
   registers) we still want to assume a conceptual stack.

..
   so that indexing does not require sophisticated calculation of offsets.
   (bit)vector of types, and summing up 32/64 bit offsets for indices
   :math:`0\dots i-1` in that vector when wanting to index to stack position
   :math:`i`.


..
   Label stack
   ^^^^^^^^^^^

   .. note::
      Maintaining a label stack should actually not be necessary as for
      branching instructions, the label's result type and the stack height when
      entering the block should be known statically. Also the target code
      position is known statically.

   Each time a block is entered, we have to remember the current height of the
   operand stack (for potential cleanup when branching) as well as the length of
   the label's arity (corresponding to the number of values expected on the
   operand stack when branching). [#stack-cleanup]_ An entry in the label stack
   thus consists of two fixed-sized numbers that can fit the maximum operand
   stack depth and the maximum label arity length, respectively.

   A separate label stack as opposed to putting labels on the operand stack
   avoids some additional cases where values would have to be moved on the
   operand stack (e.g. when inserting a label or when removing a label where
   otherwise no cleanup is necessary).

.. .. [#stack-cleanup] For details on the relevant semantics see the notes on
.. block and branch instructions below.

.. _accounting-stack-size:

Accounting for stack size
^^^^^^^^^^^^^^^^^^^^^^^^^

To be able to assume that accessing the stacks [#stack-stacks]_ is actually
cheap, we set a limit on the total stack size. We count a conceptual size which
should roughly correspond to the actual size it will have in an implementation
(at most off by a small constant factor).

The effect of most instructions is just adding or removing one value from the
operand stack. At branching and function calls it gets a bit more complicated
because of cleanup and handling function frames on the stack.

We account for stack size during execution, and when the limit is reached,
execution will abort with a failure. There are different ways of accounting,
with different tradeoffs regarding computational effort and complexity in
specification and implementation.


.. [#stack-stacks] Both frame stack and operand stack, whether they are combined
    or not should not be of much relevance.

Accounting at every instruction
-------------------------------

The most obvious way to account for stack size would be to consider the changes
with every instruction (or, as with accounting for execution cost, for sequences
of instructions that do not include branching). The advantage is that for most
instructions it is very easy to see what effect they have on stack height, and
we can account in the same way as we do for execution cost. We also get a very
precise accounting of actually used stack size. However, when it comes to
branching, because of cleanup more context from the surrounding blocks is
necessary to determine the number of values removed. The main disadvantage
though is that the accounting cost is fairly high, having to update a second
accounting variable in addition to that for execution cost. While it can be
performed during the same host function call, the additional cost for an
addition and a check should not be underestimated regarding the small cost of
many instructions.


.. _accounting-stack-size-func:

Accounting when calling a function
----------------------------------

As the maximum stack height/size for a given function is known statically, we
can alternatively account for stack size only when functions are entered and
left.

While it might seem fair to account for a stack height the function in the worst
case can use, this results in an overapproximation in the sense that we account
for stack size that might potentially not be used. Note that this is
particularly relevant for nested or even recursive function calls, as
overapproximation accumulates. However, if this condition is known, it can be
taken care that recursive functions do not have unnecessary high maximum stack
sizes.

Note that depending on the implementation, stack size may actually be allocated
for this maximum stack size the function might use when the function is invoked.
However, when we limit the maximum stack size anyway and require this space to
be available, this should not be a concern.

Refined accounting
^^^^^^^^^^^^^^^^^^

If one does not want to accept an accumulating overapproximation of stack height
with nested and recursive function calls, a more fine-grained accounting as
described in the following can be used. However, one must be able to assume that
the implementation actually behaves at least as fine-grained.

To avoid accounting for stack size a function might use after a nested function
call before having returned from that call, we can limit accounting to only
consider the instructions until the next function call. That is, there will be
accounting instructions before and after each function call. Before a function
call, we account for the stack size for the function's body until its first
function call. After a function call, we account for the stack size used by the
next instructions, again only until the next function call. Functions account
for the reduction of the current stack size before each return instruction and
at the end of the function. This is necessary as after a function returned, it
is not known what stack size it accounted for, because it can return from
different places at which different stack heights are currently accounted for.


Allocation of stack size
------------------------

Note that depending on the implementation, the stack(s) could be a pre-allocated
part of memory, or it/they will be dynamically allocated. In the latter case,
the cost of allocation should not be ommitted. Furthermore, the granularity of
allocation should be considered: at each function call, stack size for the
maximum possible usage by the function may be allocated (as opposed to the
optimization regarding recursion described above).



A note on accounting through the cost of instructions
-----------------------------------------------------

It is worth considering whether the stack size is not sufficiently limited by a
reasonable maximum cost budget we want to assume.

However, a simple calculation shows that this is probably not possible. Assuming
that we are charging similar for function locals as for a :math:`\CONST`
operation, consider the stack size that can be reached with :math:`\CONST`
operations only. Assuming a maximum execution time of 0.1s (it should be safe to
assume that it is at least that), and an execution time of the :math:`\CONST`
instruction of 5ns (:math:`5*10^{-9}` s, it should be safe to assume that it is
less), and 64 bit stack size per :math:`\CONST` instruction, we could reach a
stack size of up to :math:`64~\mbox{bit} * \frac{0.1}{5*10^{-9}} = 1.28 *
10^9~\mbox{bit}`, that is, more than 1GB. As this is way beyond an acceptable
limit, instructions' cost on their own cannot limit stack size enough (note that
the calculations are only based on the *relative* cost per execution time).

While in practice this theoretical example with a big amount of :math:`\CONST`
operations might not be possible due to restrictions on module size, an
alternative with recursive function calls would achieve something similar. It
would incur a higher cost per stack size, but regarding the high amount of stack
size calculated above, this should still lead to an unacceptable high size.


Memory considerations
^^^^^^^^^^^^^^^^^^^^^

To be able to assume for several operations / evaluation steps to be cheap in
terms of execution time, we have to be confident enough that the respective data
that is read and written resides in sufficiently fast memory (e.g. cache). To
this end, we have to impose/assume limits on several parts involved in
execution.

**Memory consuming components that need to be limited:**

* Stack size

* All linear memories allocated in modules

* Module size (particularly code
  size, to be able to jump arbitrarily between instructions/functions)


Note that also the runtime system needs some memory.


Blocks
^^^^^^

The different blocks :math:`\BLOCK`, :math:`\LOOP` and :math:`\IF` define labels
that can be used as branching targets from inside the block. We assume that
these labels, as well as the :math:`\BLOCK` and :math:`\LOOP` instructions
themselves, are not explicitly part of the eventually executed code, or at least
that they do not incur any cost in addition to actual branching instructions.

The :math:`\BLOCK` and :math:`\LOOP` markers and the implicit labels blocks
define are only needed for validation and to generate the correct target
addresses for branch instructions. In the eventual code to be executed, the
branch instructions are the only necessary semantical components, specifying the
correct instruction to continue with in the instruction sequence.

A consequence is that any amount of nested blocks do not add to accounted cost
in addition to the included other instructions.
