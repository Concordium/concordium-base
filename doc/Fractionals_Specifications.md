# Specifications on fractional numbers

This is a collection of notes on specifications regarding fractional numbers.


<a id="orgc36bb4e"></a>

### Floating point arithmetics

1.  Resources

    1.  <https://en.wikipedia.org/wiki/Floating-point_arithmetic>
    
    2.  IEEE 754 standard exceptions (flags) for underflow, overflow etc.
    
        1.  1985 and 2000 version&#x2026;
    
    3.  Decimal floating point: <https://en.wikipedia.org/wiki/Decimal_floating_point>
    
    4.  <http://christian-seiler.de/projekte/fpmath/>
    
        1.  "The best solution would probably be using the MPFR library (or something similar). That has its drawbacks though: The performance is slower than native FPU performance and it requires memory allocation on the heap. Also, having such a big library as a requirement for the own software may not always be the optimal choice. Thus a solution using the native FP unit will be built."
        
        2.  "Using single or double precision for floating point calculations seems to be the only portable alternative without using an entire library."
    
    5.  <https://docs.oracle.com/cd/E19957-01/806-3568/ncg_goldberg.html>
    
    6.  FP determinism: <https://randomascii.wordpress.com/2013/07/16/floating-point-determinism/>
    
    7.  There are also the ISO/IEC 10967, Language independent arithmetic (LIA) standards: <https://en.wikipedia.org/wiki/ISO/IEC_10967>

2.  Specifics to care about

    1.  different zeros, e.g. 1/0 != 1/-0
    
    2.  Subnormal numbers
    
        1.  Usually, the significand has no leading zeros (instead, the exponent is adapted)
        
        2.  But for very small numbers (positive and negative, that is, close to zero), there are numbers representable with leading zeros but not otherwise because the exponent is already at its minimum; these numbers are called subnormal numbers (in IEEE terminology)
        
        3.  Not having subnormals lead to malfunction software (because there was no way to detect them and programmers weren't aware of them) until the 1980s (<https://people.eecs.berkeley.edu/~wkahan/ieee754status/754story.html>)

3.  IEEE 754

    1.  IEEE 754-2008 newest revision replacing IEEE 754-1985 (extends, makes some more specifications were previously undefined)
    
        1.  Became international: ISO/IEC/IEEE 60559:2011 (<https://www.iso.org/standard/57469.html>)
    
    2.  With signed zeros: variant of extended real numberline
    
        1.  1/-0 = -inf
        
        2.  1/+0 = +inf
        
        3.  +0/-0 like approaching zero from above/below
        
        4.  Comparison: 0 == -0
        
            1.  Can get access to sign bit via copysign function (also in mpfr) or by 1/-0 1/+0
        
        5.  "Representations that allow negative zero can be a source of errors in programs, if software developers do not take into account that while the two zero representations behave as equal under numeric comparisons, they yield different results in some operations."
        
        6.  Behaviour of zeros specified under various operations, outcome may depend on the current IEEE rounding mode settings
    
    3.  Attention: specification not deterministic

4.  The General Decimal Arithmetic Specification: <http://speleotrove.com/decimal/>

    1.  Advantages
    
        1.  Can represent decimal floating points exactly. "binary floating-point arithmetic should not be used for financial, commercial, and user-centric applications or web services because the decimal data used in these applications cannot be represented exactly using binary floating-point."
        
            1.  Explanation and examples: <http://speleotrove.com/decimal/decifaq.html>
    
    2.  "More recently, the core arithmetic has been extended to include the special values and other requirements of IEEE 854 (the radix-independent generalization of IEEE 754-1985). This combined arithmetic meets commercial, scientific, mathematical, and enginering requirements, and is now included in the IEEE 754-2008 and the ISO/IEC/IEEE 60559:2011 standards."
    
    3.  Language independent specification: <http://speleotrove.com/decimal/decarith.html>
    
        1.  "The mathematical functions do not, in general, correspond to the recommended functions in IEEE 754 with the same or similar names; in particular, the power function has some different special cases, and **most of the functions may be up to one unit wrong in the last place**."
        
        2.  Arithmetic model
        
            1.  Has subnormals: "Like other numbers, subnormal numbers are accepted as operands for all operations, and may result from any operation. If a result is subnormal, before any rounding, then the Subnormal condition is raised."
            
                1.  the minimum value of the exponent becomes Emin–(precision–1)
        
        3.  Arithmetic operations
        
            1.  result is rounded exact mathematical result
            
            2.  Special cases documented
            
            3.  In general, secification seems quite good
            
            4.  Specific functions
            
                1.  exp
                
                    1.  for non-special cases: "the **result is inexact** and will be rounded using the **round-half-even** algorithm. The coefficient will have exactly precision digits (unless the result is subnormal). These inexact results **should be correctly rounded, but may be up to 1 ulp (unit in last place) in error**."
            
            5.  NOTE: There is nothing specified about trigonometric functions
        
        4.  Rouding modes
        
            1.  5 must be supported, including round-half-even (which is round-to-nearest, ties-to-even)
        
        5.  Signals
        
            1.  rounded: "raised when a result has been rounded (that is, some zero or non-zero coefficient digits were discarded)"
            
            2.  inexact: when result is not exact ("one or more non-zero coefficient digits were discarded during rounding")
            
                1.  TODO relation to "rounded"?
    
    4.  Also encodings specification: <http://speleotrove.com/decimal/decbits.html>
    
    5.  Related specifications
    
        1.  IEEE 754-2008 "includes decimal floating-point formats (as described above) and arithmetic on those formats (also described above)."
        
            1.  If that is the case, then implementation of IEEE 754-2008 are fine (except for the cases where this specification is not enough, like for exp)
        
        2.  Web assembly (checked 19-07-25): <http://webassembly.github.io/spec/core/exec/numerics.html#floating-point-operations>
        
            1.  But only very basic functions + sqrt
            
                1.  Seems they don't want to specify (natively implement) trigonometric functions: <https://github.com/WebAssembly/design/pull/264/files>
                
                    1.  Will probably have something like C's libm

