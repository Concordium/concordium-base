# Fractional numbers
We might want to use fractional datatypes in two places: in the Acorn smart contract language and in the leader election of the Birk protocol (package Concordium.Birk.LeaderElection, branch [with-mpfr](https://gitlab.com/Concordium/consensus/prototype/tree/with-mpfr)).


## General considerations / background
On Blockchain, whether used in the smart contract language or for calculations in the protocol, fractional number have to behave deterministically, so that the same behaviour is given on all platforms we support.
The most commonly used format for fractional numbers are floating-point formats based on the [IEEE 754 standard](https://en.wikipedia.org/wiki/Floating-point_arithmetic#IEEE_754:_floating_point_in_modern_computers). However, most floating-point implementations are not determinstic and depend e.g. on the CPU in use.


### Status of other Blockchains regarding fractional numbers
Other Blockchains seem to add fractional numbers to their smart contract language. As of 2019-07, did not find any working implementation yet. See [Fractionals in other Blockchains](Fractionals_in_other_Blockchains.md) for details.

### General about fractional number formats

#### Specifications
There are several specifications on floating-point formats, see [Fractionals Specifications](Fractionals_Specifications.md) for a list of resources.

#### Binary vs. decimal
Even though most implementations only support binary floating-point numbers, it should also be considered to use decimal floating-point numbers, as for some applications these might be more suitable. For further information, see the [General Decimal Arithmetic website](http://speleotrove.com/decimal/) which also links to a lot of further resources, including implementations.

#### Fixed-point
- Usually used in embedded systems where performance is critical
- Simpler format

#### Floating-point
- Used on most general-purpose platforms
- Often complex formats, difficult to implement correctly


#### Posits
Posits represent a newer format for fractional numbers which promise several advantages over the existing formats. For an introduction, see for example https://www.nextplatform.com/2019/07/08/new-approach-could-sink-floating-point-computation/amp/.

### Requirements for fractional type in Acorn

The following are the requirements that were taking into considerations when looking for a suitable library.

- *NOTE:* The use cases for fractional numbers in smart contracts are not clearly defined yet.
- The data type must have a fixed representation size
- Support of basic arithmetic operations including `exp` and `log` as well as `sin`, `cos`, `sinh`, `cosh`
  - Preferable also `pow`, `sqrt` etc.
- All operations must have specified and deterministic behaviour
  - Thus correct rounding for results which cannot be represented exactly (with the chosen precision)
    - Preferable unbiased rounding
- Precision can be fixed, at least like double type, preferable more
- Rounding
  - Being able to choose the rounding mode for an operation is a plus, as e.g. rounding to nearest integer is unbiased but not always desired in all cases (e.g. with iterated computations, example: https://www.embeddedrelated.com/showarticle/1015.php)
  - A result value which specifies whether and how it was rounded is a plus
- The computation cost for each operation should be predictable
  - This can be difficult for functions like `sin`, where libraries often use lookup-tables for certain inputs to improve performance, or exponentiation, where the cost inherently depends on the argument
- It is preferred to have checked operations that fail on overflow and underflow / NaN results
- Special values like NaN and infinities are not a requirement but a plus
- Conversion to/from integer types
- It is acceptable that on startup of the software, we check whether the platform supports certain requirements (e.g. a certain precision) and fail with an error if not.

## MPFR

### Suitability of MPFR

MPFR matches our requirements:
- The specification basically follows IEEE 754 except for a few documented exceptions
- Results are reproducable on computers with different operating system, word size or compiler
- Results are as if computed exactly and then rounded to the specified precision
- Different rounding modes, including rounding to nearest integer (= unbiased)
- Precision can be set exactly, very high precision possible
  - Can reproduce the C double type behaviour


#### To be checked

- Have to check the specification of each operation in detail, and test it properly, before using
- Find out actual memory and computation cost for each operation and whether it is deterministic

### Some notes on MPFR

- Some parameters for MPFR are system dependent, but we can check for our requirements on startup and stop the program if they are not satisfied
  - The allowed values for setting the precision with `mpfr_set_emin` and `mpfr_set_emax` are system-dependent but it can be checked whether setting was successful
  - Setting precision close to MPFR_PREC_MAX can result in assertion failure (see 4.2)
- "Moreover, you may reach some memory limit on your platform, in which case the program may abort, crash or have undefined behavior (depending on your C implementation)." (4.2)
- Upcoming changes in future versions
  - For division, for types without signed zero (only those I guess) x/0 might change from +inf/-inf (which it is now as 0 considered +0) to NaN if IEEE 754 decides so
    - However, if we use division only on MPFR numbers, this should not be a problem
  - Might want to look at the TODO in the MPFR distribution

### Some technical points to consider when using MPFR
- MPFR uses GNU GMP
- Haskell links to GMP (this could cause problems when the haskell program itself then also links to MPFR/GMP)
- GCC comes with MPFR
- GNU GCC requires GMP and MPFR


### Haskell library for MPFR: [Hmpfr](https://hackage.haskell.org/package/hmpfr)

#### Suitability
Hmpfr seems to provide what we need (regarding its specific task of providing bindings to MPFR, in addition to the properties MPFR provides):
- It provides bindings to the needed arithmetic operations in `Data.Number.MPFR.Arithmetic` and `Data.Number.MPFR.Special`
- It provides assignment functions from `Word`, `Int` and `Double` (`Data.Number.MPFR.Assignment`) as well as conversion to these types and `String` (`Data.Number.MPFR.Conversion`)
- It allows to set the exponent range through `mpfr_set_emin` and `mpfr_set_emax` in `Data.Number.MPFR.FFIhelper` (but probably MPFR's the default range is just fine)

The bugs/problems mentioned allow are not a problem for our use cases.

#### Bugs

##### Random number generation
- Hmpfr only provides binding for `urandomb` even though MPFR has more random number generation functions
- `urandomb` in `Data.Number.MPFR.Misc` is returning the same number on each invocation (tested on Linux), also the project's [example](https://github.com/michalkonecny/hmpfr/blob/master/demo/Demo.hs).
- About current implementation of `urandomb`:
  - `newRandomStatePointer` in `Data.Number.MPFR.Misc` does `unsafePerformIO new_gmp_randstate`
  - `urandomb :: Ptr GmpRandState -> Precision -> MPFR`
  - foregin call `mpfr_urandomb_deref_randstate ::  (Ptr MPFR) -> (Ptr GmpRandState) -> IO Int` in `Data.Number.MPFR.FFIhelper`

#### Alternatives
There is another Haskell library providing bindings to MPFR: [haskell-mpfr](https://hackage.haskell.org/package/haskell-mpfr).

### Tests
For tests of MPFR and hmpfr see package [MPFRTest](../MPFRTest).

#### Leader election with MPFR
With a manually built MPFR 4.0.2 on Windows, could successfully run Concordium-exe with a leader election using MPFR fractionals (branch with-mpfr on prototype repository, 2019-08, commit fe92cdde4491c81703156da43887a9d66e144561).

### MPFR on Windows
For how to build and run MPFR with stack under Windows, see [MPFRWindows](MPFRWindows.md).
For distribution, we might want to use a prebuilt MPFR library.

### License
From the MPFR documentation for version 4.0.2:

> This version of MPFR is released under the GNU Lesser General Public License, version 3 or
> any later version. It is permitted to link MPFR to most non-free programs, as long as when
> distributing them the MPFR source code and a means to re-link with a modified MPFR library
> is provided.

## Alternative libraries

### General
Did an extensive web search 2019-07 but no other library than MPFR matched our requirements enough.
In general it seems like floating-point libraries are more mature and complete than fixed-point libraries, for which there really cannot be found much.

For the floating-point libraries, it seems that most libraries seem to be more performance-oriented and do not care about precision and determinism.

### MPFR-related
- Checked forks of MPFR 2019-07-24 but did not find anything relevant

### Other libraries

Notes on libraries considered can be found under [Notes on fractional numbers libraries](Fractionals_libraries.md).
Note that it might be worth checking the status of some libraries again, as some were still under development.

## Own implementation

It is also an option to implement an own fractional numbers library (then using for example posits) or forking one of the projects mentioned above and add the missing functionality.
Some libraries actually seem to be of good quality and taking them as a starting point might make sense (e.g. [LibBF](https://bellard.org/libbf/)).
