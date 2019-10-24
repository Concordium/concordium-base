# MPFR Test

This package contains some tests to check the suitability of the [GNU MPFR Library](https://www.mpfr.org/) as well as the Haskell library [hmpfr](http://hackage.haskell.org/package/hmpfr) (providing Haskell bindings to MPFR) for on-chain use.

## Tests

The purpose of the tests is to check whether MPFR does not crash under "stress" situations (e.g. a lot of allocations and deallocations per time, a lot of numbers allocated at the same time) and whether hmpfr introduces memory leaks.

### Running the tests
- Make sure that parallel execution is enabled
- Run `stack run --profile --rts-options '+RTS -hy'` for heap profiling

### Successfully tested

The following test names are the names of the functions from [app/Main.hs](app/Main.hs) which were run at commit 2c0c7c5f296fffb5e0a1cf46032c0f0384b91a46. See this file for details on the tests.

Tests were run with MPFR 4.0.2 on the following systems:
- Arch Linux with MPFR from Arch repositories (`core/mpfr 4.0.2-1`) on Thinkpad X1 Carbon 6th Gen with Intel Core i7-8550U, 16 GB LPDDR3 2133 MHz RAM
- Windows 10 on Intel Core i5-4200M CPU @ 2.50GHz, 16GB RAM

On both Linux and Windows, all test ran in max. a few minutes (with profiling). The corresponding heap profiling diagrams (`-hy` profiling option) can be found under [profiling](profiling) (the file names are composed of the function names and the parameters as given in [app/Main.hs](app/Main.hs)).

#### Stress tests
  - **runSuccessiveRandomOpsParallel:** A sequence of MPFR numbers "rotated" by applying randomly chosen operations on the elements at the front, putting the results at the back. Run in parallel on multiple threads.
    - Operations uniformly chosen from `+,-,*,/,sqr,sqrt,exp,log`
    - Run with the following parameters (amount of numbers = amount kept in the sequence):
      - 4 threads, 10^5 numbers 100-bit numbers, 10^6 operations (memory usage goes up to ca. 550 MB)
      - 4 threads, 10^6 numbers 100-bit numbers, 10^5 operations (memory usage goes up to ca. 1 GB)
      - 4 threads, 10^6 numbers 100-bit numbers, 10^6 operations (memory usage goes up to ca. 2 GB)
  - **runMixedMPFRIntegerParallel:** Intermingled allocation of large Integers and MPFR numbers, in parallel on multiple threads. The possible reason is that Haskell might use GMP for big numbers, and as MPFR uses GMP as well, there could be issues.
    - Run with the following parameters:
      - 4 threads, 10^5 numbers   1000-bit numbers (memory usage goes up to ca. 230MB)
      - 4 threads, 10^5 numbers  10000-bit numbers (memory usage goes up to ca. 850MB)
      - 4 threads, 10^5 numbers 100000-bit numbers (memory usage goes up to ca. 6.5GB)
        - Still only taking a few seconds
        - One run crashed on Linux with `get_str.c:157: MPFR assertion failed: size_s1 >= m`
      - 4 threads, 10^6 numbers 100-bit numbers (memory usage goes up to ca. 1.8 GB)

#### Tests for memory leaks
  - **simpleSum:** Sum up a lot of MPFR numbers, thus resulting in a lot of allocations and deallocations.
    - Note that this only tests for memory leaks from the Haskell side, as the profiling done does not cover allocations done by MPFR itself
    - Run with the following parameters:
      - 10^5/10^6/10^7  100-bit MPFR numbers
      - 10^5/10^6      1000-bit MPFR numbers
    - All resulting sums were normal values (no `NaN` or infinities)
    - No memory leak detected (memory usage stays constantly low, whole program stays at around 210kB memory usage)
  - **simpleSumRepeated:** as *simpleSum* but sum up the numbers twice, so that they are kept in memory
    - Run with the following parameters:
      - 10^5/10^6  100-bit MPFR numbers
      - 10^5/10^6 1000-bit MPFR numbers
    - (with 10^7 100-bit numbers the memory usage continues to grow but the run is not completed after ~30min with 3.5GB (probably need around 5-6GB))

### Still to be tested

- Stress tests with all MPFR operations that will be used
