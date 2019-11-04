
# Table of Contents

1.  [Notes on fractional numbers libraries](#orgf7dafe7)
    1.  [Fixed-point](#orgcbc40b8)
        1.  [[no] https://code.google.com/archive/p/libfixmath/](#org4966172)
        2.  [[maybe] https://github.com/Pharap/FixedPointsArduino](#org237fc59)
        3.  [[maybe] https://www.codeproject.com/Articles/37636/Fixed-Point-Class](#org9b0fe7b)
        4.  [[probably not] https://github.com/gbmhunter/MFixedPoint](#org9819754)
        5.  [[probably not] https://opencores.org/projects/verilog\_fixed\_point\_math\_library](#org328884c)
    2.  [Floating-point](#org69a3cd3)
        1.  [[rather not] MathCW: http://ftp.math.utah.edu/pub/mathcw/](#org4e3ce7b)
        2.  [[probably not] NTL](#org914c75d)
        3.  [[rather not] Intel Decimal Floating-Point Math Library: https://software.intel.com/en-us/articles/intel-decimal-floating-point-math-library](#org9fae88b)
        4.  [[rather not] decNumber: http://speleotrove.com/decimal/#decNumber](#org0ae13da)
        5.  [[maybe extend] libmpdec (mpdecimal): http://www.bytereef.org/mpdecimal/](#org87a3bcc)
        6.  [[maybe base on] libbf: https://bellard.org/libbf/](#org4ff1b01)
        7.  [[rather not] MPIR: http://mpir.org/index.html](#org85b1694)
        8.  [[maybe] CLN ("efficient computations with all kinds of numbers in arbitrary precision")](#orgce1ee0f)
        9.  [[rather not] libmcr: https://github.com/simonbyrne/libmcr](#org6ebe9b7)
        10. [[rather not] Decimal-enabled GCC (from 4.2, 2007)](#org18f5c63)
        11. [Maybe](#orgd912fa1)
        12. [[no] https://github.com/huonw/float](#org09c6450)
        13. [MPC](#orge12a07c)


<a id="orgf7dafe7"></a>

# Notes on fractional numbers libraries

Composed from an extensive web search 2019-07. MPFR is not included here.
Note that these notes are not extensive or well-formulated but might give some quick information on some libraries.


<a id="orgcbc40b8"></a>

## Fixed-point


<a id="org4966172"></a>

### [no] <https://code.google.com/archive/p/libfixmath/>

1.  W: platform-independent

2.  Doesn't seem very major (bugs)

3.  A: Problem: just Q16.16.

4.  Doesn't seem to be developed further


<a id="org237fc59"></a>

### [maybe] <https://github.com/Pharap/FixedPointsArduino>

1.  Seems okay but project probably too small

2.  Functions

    1.  Only has the basic arithmetic operators


<a id="org9b0fe7b"></a>

### [maybe] <https://www.codeproject.com/Articles/37636/Fixed-Point-Class>

1.  Functions

    1.  Has exp, sqrt, sin
    
    2.  For sin/cos uses "MacLaurin series expansion"
    
        1.  But doc


<a id="org9819754"></a>

### [probably not] <https://github.com/gbmhunter/MFixedPoint>

1.  "Casting to an int rounds to negative infinity"

2.  FpS64 not protected from intermediate overflows


<a id="org328884c"></a>

### [probably not] <https://opencores.org/projects/verilog_fixed_point_math_library>

1.  has specification: <https://opencores.org/projects/verilog_fixed_point_math_library/manual>

    1.  checking for overflow is up to the "designer" (probably hardware)

2.  but a bit strange, have to login to download, &#x2026;


<a id="org69a3cd3"></a>

## Floating-point


<a id="org4e3ce7b"></a>

### [rather not] MathCW: <http://ftp.math.utah.edu/pub/mathcw/>

1.  Need base conversion?

2.  Has decimal and fp

3.  Unfortunately not open source yet ("Library source code will be released when a large book that documents it is published. At the time of writing this, that date is still uncertain, but might be in late 2010.")

    1.  documentation as man pages
    
        1.  not sure yet whether good enough

4.  Also linked from MPFR webpage

5.  book linked from W (FP, further reading): "The Mathematical-Function Computation Handbook: Programming Using the MathCW Portable Software Library" (2017, 120€ / FP chaper 31€)

    1.  Seems to be a decent book (written by the library author (University of Utah))
    
    2.  "The approach taken in the mathcw library is to provide the C99 interface to IEEE 754 features by implementing them in terms of whatever support is provided by the underlying operating system. Fortunately, on all U NIX systems, that has been possible without having to resort to processor-specific assembly language, except for access to precision control."
    
    3.  "Although there are similarities in the handling of the IEEE 754 environment among some of those operating systems, for clarity and reduction of code clutter, the mathcw library code provides separate implementations of the C99 interface for each of them. A fallback implementation is provided when the host operating system is not supported, or does not have IEEE 754 arithmetic. The implementation behaves sensibly, so that code that uses the C99 routines can function, as long as it is prepared to handle a system that lacks some, or all, of the features of IEEE 754 arithmetic."

6.  Info from webpage

    1.  portable C library, interfaces to C++, C#, Java, &#x2026;
    
    2.  Code considered stable, tested on many different Unix platforms, occasionally on Windows with Cygwin
    
    3.  Compilers with decimal arithmetic support: <http://ftp.math.utah.edu/pub/mathcw/dgcc/> (this is more up-to-date (2018))

7.  For decimal floating-point support need gcc with decimal support

8.  Rounding?

    1.  What mode?
    
    2.  Deterministic rounding?
    
    3.  Slides: High relative accuracy: target is two ulps but exp, log, root, sin etc. *almost* always correctly rounded

9.  Specification of functions

    1.  exp seems fine
    
        1.  NaN for NaN
        
        2.  If value too large to represent: infinity, errno flat got ERANGE
        
        3.  But what kind of rounding is used?
    
    2.  add: "Underflow, overflow, and invalid operation are possible."

10. A Problem

    1.  Should not depend on one person
    
    2.  Documentation doesn't really look good
    
    3.  Need sth. we can take control over sth. widely used (not just rely on one guy)


<a id="org914c75d"></a>

### [probably not] NTL

1.  MPFR says: "The RR class from NTL, which implements a "smooth extension" of IEEE floating point to arbitrary precision and guarantees a platform-independent behaviour."

2.  Summary

    1.  Would be a good candidate, but has no correct rounding for transcendental functions (only accurracy guarantee)

3.  Seems decent with extensive documentation but not for single functions (not enough in class headers (RR class seems fine!?), other doc just general about library)

    1.  Seems still maintained (still updated in 2018), longexisting (since 1990)
    
        1.  Website:
        
            "I plan to continue supporting NTL, fixing bugs and improving performance.
            While I don't have time to add significant new functionality to NTL, there seems to be an ever-growing number of NTL users out there, and I encourage them to make their code available to others. These might be in the form of NTL "add ons", but there is the possibility of integrating new functionality or algorithmic improvements into NTL itself."
    
    2.  Author got price: <http://www.sigsam.org/awards/jenks/awardees/2015/> (Richard Dimick Jenks Memorial Prize for Excellence in Software Engineering applied to Computer Algebra)
    
        1.  Lib can also do FFT-based polynomial arithmetic
        
        2.  "NTL is a computer algebra library that does several basic computer algebra and number theory tasks exceptionally well, and therefore has been put into use in other open source computer algebra software, e.g., SINGULAR."
    
    3.  LGPLv2.1+

4.  high-performance C++ library

    1.  can be built in conjunction with GMP for enhanced performance
    
    2.  " NTL's polynomial arithmetic is one of the fastest available anywhere, and has been used to set "world records" for polynomial factorization and determining orders of elliptic curves"

5.  Portable: "NTL can be easily installed in a matter of minutes on just about any platform, including virtually any 32- or 64-bit machine running any flavor of Unix, Mac OS, or Windows."

    1.  Details (must pay attention): <https://www.shoup.net/ntl/doc/tour-impl.html>
    
        1.  E.g. that compilers behave correctly, not too high optimization levels
    
    2.  Installation instructions for UNIX and Windows

6.  Arbitrary precision floating-point arithmetic

    1.  "All arithmetic operations are implemented so that the effect is as if the result was computed exactly, and then rounded to p bits." (<https://www.shoup.net/ntl/doc/RR.cpp.html>), can set precision
    
        1.  But for transcendental functions and pow not; still "strong accuracy condition" though: "**the computed result has a relative error of less than 2<sup>-p + 1</sup>**
        
            (and actually much closer to 2<sup>-p</sup>).
            That is, it is as if the resulted were computed exactly, and then
            rounded to one of the two neighboring p-bit numbers (but not necessarily
            the closest)."
            
            1.  Here need to know exact behaviour though, at least it must not be machine dependent (which it is claimed not to be)
            
            2.  What we could do is work-around the error by temporarily increasing the precision by one bit and then rounding away the last digit again (for which it provides to<sub>RR</sub> or conv)
    
    2.  Example
    
        "If x and y are computed to 200 bits of precision,
        and then the precision is set to 100 bits, then x-y will
        be computed correctly to 100 bits, even if, say, x and y agree
        in their high-order 50 bits.  If x and y had been rounded to
        100 bits before the subtraction, then the difference would
        only be accurate to 50 bits of precision."

7.  Rounding

    1.  Default: round-to-nearest

8.  xdouble

    1.  almost as double, but with extended exponent range
    
    2.  There is, however, not much documentation in the class file

9.  BUT:

    "Unlike IEEE standard floating point, there are no "special values",
    like "infinity" or "not a number", nor are there any "denormalized
    numbers".  Overflow, underflow, or taking a square root of a negative
    number all result in an error being raised."
    
    1.  If we only provide checked operations, that would be okay

10. Using

    1.  A: Doc for special functions? Would need to know result
    
        1.  Have to find out, then the lib is a candidate
    
    2.  A: would have to write C wrapper around the C++ lib


<a id="org9fae88b"></a>

### [rather not] Intel Decimal Floating-Point Math Library: <https://software.intel.com/en-us/articles/intel-decimal-floating-point-math-library>

1.  implements IEEE 754-2088 Decimal Floating-Point specification

2.  Linux, Windows, MacOS, +more

3.  documentation?

    1.  some: <http://www.netlib.org/misc/intel/README.txt>
    
    2.  Does not really say whether platform-independent
    
    3.  A: looks like caring about performance but not for documentation


<a id="org0ae13da"></a>

### [rather not] decNumber: <http://speleotrove.com/decimal/#decNumber>

1.  decimal floats using IEEE 754 encoding

    1.  arbitrary precision + much faster decFloats using the IEEE 754 decimal encodings to implement the decSingle, decDouble, decQuad datatypes
    
    2.  A: specific parts of the standard; if it implements extra things from 2008 standard, maybe it is determinsitic
    
    3.  "This document describes the decNumber ANSI C implementation of General Decimal Arithmetic" (<http://speleotrove.com/decimal/decnumber.html>)

2.  Like libmpdec no sin/cos (according to list here: <http://speleotrove.com/decimal/dnnumb.html>)

3.  Rounding

    1.  "the mathematical functions in the decNumber module do not, in general, correspond to the recommended functions in IEEE 754 with the same or similar names; in particular, the power function has some different special cases, and **most of the functions may be up to one unit wrong in the last place** (note, however, that the squareroot function is correctly rounded)"
    
        1.  This is as stated in the General Decimal Arithmetic Specification where it later also states that operations are as if computed exactly and then rounded

4.  Functions

    1.  decNumberExp(number, rhs, context)
    
        1.  Like in spec, result may have error (up to one ulp)
    
    2.  **No trignometric functions**

5.  in use on dozens of different platforms (20 Unix varieties, mainframe, &#x2026;), Windows not explicitly listed

6.  Mike Cowlishaw is also involved in IEEE 754 2019 revision

7.  Source code: <https://github.com/gcc-mirror/gcc/tree/master/libdecnumber>


<a id="org87a3bcc"></a>

### [maybe extend] libmpdec (mpdecimal): <http://www.bytereef.org/mpdecimal/>

1.  "complete implementation of the General Decimal Arithmetic Specification" (spec by Mike Cowlishaw, IBM, see decNumber)

    1.  "The specification, written by Mike Cowlishaw from IBM, defines a general purpose arbitrary precision data type together with **rigorously specified functions** and **rounding behavior**. As described in the scope section of the specification, libmpdec will - with minor restrictions - also conform to the IEEE 754-2008 Standard for Floating-Point Arithmetic, provided that the appropriate context parameters are set."
    
        1.  Links to specification: <http://speleotrove.com/decimal/decarith.html>
    
    2.  It is the basis of Python 3.3 decimal module
    
    3.  A: seems good and easy to use

2.  Data type mpd<sub>t</sub>

    1.  Consists of exponent (of mpd<sub>ssize</sub><sub>t</sub>) and an array of words for the significand, plus flags etc.
    
    2.  Precision is controlled by context given to operations, also for assignments from integer/string (but not for special values
    
        1.  So basically can set precision for each operation, if we use just one fixed precision, there should be no problems

3.  Checking requirements for functions

    1.  add,sub,mul,div: no special notes (thus see specification)
    
    2.  sqrt: rounds correctly, rounding ROUND<sub>HALF</sub><sub>EVEN</sub>
    
    3.  exp,ln: rounds correctly if configured so (allcr field in context)
    
        1.  in contrast to specification; have to verify carefully
    
    4.  **NO SIN/COS** etc.! (see spec)
    
    5.  Conversion functions: from/to integer and string

4.  Library facts

    1.  License: Simplified BSD
    
    2.  Latest stable release: 2016-02-28 v2.4.2
    
    3.  Cross-plaform (tested Linux, Windows and more)


<a id="org4ff1b01"></a>

### [maybe base on] libbf: <https://bellard.org/libbf/>

1.  Summary

    1.  Sounds like a candidate for further development

2.  Library info

    1.  MIT, last version 2019-02
    
    2.  Principles: "LibBF is a small library to handle arbitrary precision floating point numbers. Its compiled size is about 60 KB of x86 code and has no dependency on other libraries. It is not the fastest library nor the smallest but it tries to be simple while using asymptotically optimal algorithms. The basic arithmetic operations have a near linear running time."
    
    3.  Portability: As it is only a few C files it is probably platform-independent
    
        1.  But what requirements are there on word size etc.?
        
        2.  see maybe Makefile

3.  Technical doc: <https://bellard.org/libbf/readme.txt>

    1.  done reading

4.  Rounding/Features

    1.  "All operations are **exactly rounded** using the 5 IEEE 754 rounding modes (round to nearest with ties to even or away from zero, round to zero, -/+ infinity). The additional **non-deterministic faithful rounding** mode is supported when a lower or **deterministic running time** is necessary."
    
    2.  "Exactly rounded floating point input and output in any base between 2 and 36 with near linear runnning time."
    
    3.  "Unlike other libraries (such as MPFR [2]), the numbers have no attached precision. The general rule is that each operation is internally computed with infinite precision and then rounded with the precision and rounding mode specified for the operation."
    
    4.  "The faithful rounding mode (i.e. the **result is rounded to - or +infinity non deterministically**) is supported for all operations. It usually gives a faster and deterministic running time. The transcendental functions, inverse or inverse square root are internally implemented to give a faithful rounding. When a non-faithful rounding is requested by the user, the Ziv rounding algorithm is invoked."

5.  Functions

    1.  exp, log, pow, sin, cos, tan, asin, acos, atan, atan2
    
        1.  TODO Problem that doesn't have sinh?
        
            1.  A: don't have to specify it for a primitive, can be an acorn library function
        
        2.  Implementation of exp: doesn't seem trivial; does Taylor expansion
        
            1.  For bf<sub>exp</sub><sub>internal</sub> it says "Compute the exponential using faithful rounding at precision 'prec'." and "the algorithm is from MPFR"
            
            2.  So somehow it must make sure to reach the correctly rounded value&#x2026; (and there is no proof as it says)

6.  Problems

    1.  "In some operations (such as the transcendental ones), there is no rigourous proof of the rounding error. We **expect to improve it** by reusing ideas from the MPFR algorithms. Some **unlikely overflow/underflow cases are also not handled in exp or pow**."
    
        1.  A: what are those cases?

7.  Functions

    1.  Has exp, log, pow, sin, &#x2026;
    
    2.  IEEE 754 status flags are returned by each operation

8.  Tested using MPFR


<a id="org85b1694"></a>

### [rather not] MPIR: <http://mpir.org/index.html>

1.  Summary

    1.  MPIR (GMP fork)
    
        1.  Operations specified to calculate with infinite precision and then truncate
        
            1.  not even clear spec because depends on impl
        
        2.  No overflow/underflow detection
        
        3.  Reults often differ based on word-size of computer
        
            1.  A: not completely impossible because of this

2.  Library info

    1.  "MPIR began as a fork of GMP so they share much code. The most obvious difference is that MPIR can be compiled by MS Visual Studio with optimized assembly language support." (<https://stackoverflow.com/a/13599119/905686>)
    
    2.  Seems still maintained ("community maintained") but situation doesn't seem so sure
    
        1.  But it is used quite a bit: <http://mpir.org/links.html>
        
        2.  Developed by several authors since 2008: <http://mpir.org/authors.html>
        
        3.  Portability
        
            1.  Problem: Windows/Linux versions not synchronized: <https://github.com/wbhart/mpir/issues/272>
            
            2.  but maybe can still build using mingw?
            
            3.  Linux/OSX: <https://github.com/wbhart/mpir>
            
            4.  Windows: <https://github.com/BrianGladman/mpir>
    
    3.  <https://en.wikipedia.org/wiki/MPIR_(mathematics_software)>
    
    4.  Documentation
    
        1.  For old releases, see PDF on webpage (<http://mpir.org/downloads.html>)
        
        2.  For newer, have to build/execute sth. to get documentation (see INSTALL)
        
            1.  Raw doc: <https://github.com/BrianGladman/mpir/blob/master/doc/mpir.texi>
    
    5.  Bindings
    
        1.  PDF doc says under "Language bindings": "The following packages and projects offer access to MPIR from languages other than C, though perhaps with varying levels of functionality and efficiency."
        
            1.  TODO Links Haskell to <http://www.haskell.org/ghc/> - what does that mean?
            
            2.  But in the same way says that NTL would offer access to MPIR

3.  Specification (from 3.0.0. pdf)

    1.  "All calculations are performed to the precision of the destination variable. Each function is defined to calculate with “infinite precision” followed by a **truncation to the destination precision**, but of course the work done is only what’s needed to determine a result under that definition."
    
    2.  "mpf functions and variables have no special notion of infinity or not-a-number, and **applications must take care not to overflow the exponent or results will be unpredictable**. This might change in a future release."
    
    3.  "Note that the mpf functions are not intended as a smooth extension to IEEE P754 arithmetic. In particular **results obtained on one computer often differ from the results on a computer witha different word size**."
    
        1.  Doesn't seem reliable; maybe even not if we can assume a certain word size

4.  I guess with truncation and having self to check for overflow/underflow(?) doesn't make sense (can detect overflow?)


<a id="orgce1ee0f"></a>

### [maybe] CLN ("efficient computations with all kinds of numbers in arbitrary precision")

1.  Should be cross-plattform because C++ classes

2.  "CLN does **not implement features like NaNs, denormalized numbers and gradual underflow**. If the exponent range of some floating-point type is too limited for your application, choose another floating-point type with larger exponent range. "

3.  Rounding

    1.  "CLN rounds the floating-point results of the operations +, -, \* , /, sqrt according to the “round-to-even” rule: It first computes the exact mathematical result and then returns the floating-point number which is nearest to this."
    
        1.  There is not much more on error
    
    2.  The transcendental functions return an exact result if the argument is exact and the result is exact as well. Otherwise **they must return inexact numbers** even if the argument is exact. For example, cos(0) = 1 returns the rational number 1.
    
        1.  Does not say whether **correctly** rounded


<a id="org6ebe9b7"></a>

### [rather not] libmcr: <https://github.com/simonbyrne/libmcr>

1.  MPFR says no longer maintained

2.  See also <https://www.math.utah.edu/cgi-bin/man2html.cgi?/usr/local/man/man3/libmcr.3>

3.  web presence a bit strange, not much to be found (originally by Sun but not on their site)

4.  Rounds correctly

    1.  But: second rounding for **float wrappers** with very low probably uncorrect rounding

5.  Similarly: crlibm (suberseeded by MetaLibm which uses MPFR), libultim


<a id="org18f5c63"></a>

### [rather not] Decimal-enabled GCC (from 4.2, 2007)

1.  "first GCC release with support for the proposed ISO C extensions for decimal floating point."

    1.  How can one make use of that? Probably write C code using this
    
    2.  Ref to Beebe: <http://ftp.math.utah.edu/pub/mathcw/dgcc/>
    
        1.  Explains how to build compiler
    
    3.  TODO check whether those ISO C extensions have the specification we need
    
        1.  ISO/IEC TS 18661-2:2015 <https://www.iso.org/standard/68882.html>
        
            1.  Diffucult to find, draft 2019: <http://www.open-std.org/jtc1/sc22/wg14/www/docs/n2341.pdf>
        
        2.  ISO/IEC TR 24732:2009 (older) <https://www.iso.org/standard/38842.html>
        
            1.  superseeded by 18661-2:2015 (W)
    
    4.  GCC
    
        1.  has only basic operations (<https://gcc.gnu.org/onlinedocs/gcc/Decimal-Float.html>)
        
            1.  Thus, would have to add other operations anyway&#x2026;
        
        2.  "As an extension, GNU C supports decimal floating types as defined in the N1312 draft of ISO/IEC WDTR24732. Support for decimal floating types in GCC will evolve as the draft technical report changes. Calling conventions for any target might also change. Not all targets support decimal floating types."
        
        3.  Have to check whether specified enough


<a id="orgd912fa1"></a>

### Maybe

1.  apfloat: on first view not that matching <http://www.apfloat.org/apfloat/>

2.  MAPM <https://github.com/LuaDist/mapm>

    1.  rather looks like "thinks is correct" (because tested) but doesn't seem that trustworthy


<a id="org09c6450"></a>

### [no] <https://github.com/huonw/float>

1.  Rust

2.  correctly rounding

3.  not enough operations


<a id="orge12a07c"></a>

### MPC

1.  Similar documentation to MPFR (PDF has similar structure)

2.  Same problem as MPFR

