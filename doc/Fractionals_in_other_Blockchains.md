
# Table of Contents

1.  [Fractionals in other blockchains](#org8dd01ad)
    1.  [Etherum](#orgfce8a66)
        1.  [19-07-23: https://solidity.readthedocs.io/en/develop/types.html#fixed-point-numbers](#org0b776ca)
    2.  [Tezos](#org89b4b47)
        1.  [Repository https://gitlab.com/tezos/tezos](#orgf2ff575)
    3.  [Dfinity](#org97a6b2b)
        1.  [Repositories: https://github.com/dfinity](#orgf966baa)
    4.  [Cordano (https://www.cardano.org/en/home/)](#orgba390c2)
        1.  [Repository (link from website): https://github.com/input-output-hk/cardano-sl/](#org933e941)
        2.  [Nothing for: Floating point, fixed point, fractionals](#org992d685)
    5.  [Corda](#org18f9b03)
        1.  [Keywords: Floating point, fixed point, fractionals](#org57a33d5)
        2.  [Non-determinism in JVM https://github.com/corda/corda/blob/aa75157273dc12d7f5183873780bacd35360eb5f/docs/source/key-concepts-djvm.rst#id3](#org1c07c98)
    6.  [zCash: https://github.com/zcash](#org4c82544)
        1.  [Not really anything relevant for: Floating point, fixed point, fractionals](#orgb17bf70)
    7.  [Ziliqa (19-08-06)](#org67ccaae)
        1.  [Repository: https://github.com/Zilliqa/Zilliqa](#org5b42705)
        2.  [Nothing for: fractional, floating point, fixed point](#org5874e7c)


<a id="org8dd01ad"></a>

# Fractionals in other blockchains

The status of the following notes is from 2019-07 if not otherwise noted. The notes are mostly about keywords searched for in the repositories.


<a id="orgfce8a66"></a>

## Etherum


<a id="org0b776ca"></a>

### 19-07-23: <https://solidity.readthedocs.io/en/develop/types.html#fixed-point-numbers>

1.  "Fixed point numbers are not fully supported by Solidity yet. They can be declared, but cannot be assigned to or from." (still the same 2019-10-22)

    1.  Searched source code on github, also only placeholders / "unimplemented" assertions: <https://github.com/ethereum/solidity/search?p=2&q=fixed+point&unscoped_q=fixed+point>

2.  Has number literal types with decimal fractional literals, also with scientific notations, e.g. 2.5e1

    1.  Number literal expressions are converted into a non-literal type as soon as they are used with non-literal expressions.
    
    2.  Number literal expressions retain arbitrary precision
    
        1.  "Number literal expressions retain arbitrary precision until they are converted to a non-literal type (i.e. by using them together with a non-literal expression or by explicit conversion). This means that computations do not overflow and divisions do not truncate in number literal expressions."
        
        2.  So probably literal operations are symbolic; ("division on literals results in fractional values of arbitrary precision")
        
            1.  Because otherwise "1/3" could not be represented with arbitrary precision&#x2026;
        
        3.  Can even do "(2\*\*800 + 1) - 2\*\*800"


<a id="org89b4b47"></a>

## Tezos


<a id="orgf2ff575"></a>

### Repository <https://gitlab.com/tezos/tezos>

1.  "Fractional": only ocaml conversion functions from float to int&#x2026;

2.  "Floating point": nothing

3.  "Fixed point": nothing


<a id="org97a6b2b"></a>

## Dfinity


<a id="orgf966baa"></a>

### Repositories: <https://github.com/dfinity>

1.  Not much for: Fractionals, floating, fixed point

2.  winter

    1.  Only listing of operations on floats as haskell datatypes: <https://github.com/dfinity/winter/blob/1cea7652f48fad348af914cb6a56b39f8dd99c6a/src/Wasm/Syntax/Ops/Float.hs> and conversion
    
    2.  And implementation using haskell operations, no sin etc. <https://github.com/dfinity/winter/blob/1cea7652f48fad348af914cb6a56b39f8dd99c6a/src/Wasm/Exec/EvalNumeric.hs>

3.  Haskell to webassembly compiler: <https://github.com/dfinity/dhc>

    1.  No float operations supported

4.  Haskell port of the WebAssembly OCaml interpreter: <https://github.com/dfinity/winter> (<https://github.com/WebAssembly/spec/tree/master/interpreter>)


<a id="orgba390c2"></a>

## Cordano (<https://www.cardano.org/en/home/>)


<a id="org933e941"></a>

### Repository (link from website): <https://github.com/input-output-hk/cardano-sl/>


<a id="org992d685"></a>

### Nothing for: Floating point, fixed point, fractionals


<a id="org18f9b03"></a>

## Corda


<a id="org57a33d5"></a>

### Keywords: Floating point, fixed point, fractionals


<a id="org1c07c98"></a>

### Non-determinism in JVM <https://github.com/corda/corda/blob/aa75157273dc12d7f5183873780bacd35360eb5f/docs/source/key-concepts-djvm.rst#id3>

1.  They want a deterministic JVM: <https://docs.corda.net/key-concepts-djvm.html>

2.  What they do: "Sets the strictfp flag on all methods, which requires the JVM to do floating point arithmetic in a hardware independent fashion. Whilst we anticipate that floating point arithmetic is unlikely to feature in most smart contracts (big integer and big decimal libraries are available), it is available for those who want to use it." (<https://github.com/corda/corda/blob/aa75157273dc12d7f5183873780bacd35360eb5f/docs/source/key-concepts-djvm.rst#always-use-strict-floating-point-arithmetic>)

    1.  strictfp modified for classes/methods etc. (but does not bring us much further): <https://en.wikipedia.org/wiki/Strictfp>\_
    
    2.  So how does the JVM do it?


<a id="org4c82544"></a>

## zCash: <https://github.com/zcash>


<a id="orgb17bf70"></a>

### Not really anything relevant for: Floating point, fixed point, fractionals


<a id="org67ccaae"></a>

## Ziliqa (19-08-06)


<a id="org5b42705"></a>

### Repository: <https://github.com/Zilliqa/Zilliqa>


<a id="org5874e7c"></a>

### Nothing for: fractional, floating point, fixed point

