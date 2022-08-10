# Building and using MPFR under Windows

These notes were compiled when testing MPFR on Windows 2019-08, using the documentation for MPFR 4.0.2.

## Building GMP and MPFR

### Useful information from documentation
- Remember that if you have several MPFR (or GMP) versions installed
(e.g., one with the system, and one, newer, by you), you will not
necessarily get a compilation/linking error if a wrong library is
used (e.g., because LD_LIBRARY_PATH has not been set correctly).
But unexpected results may occur.
- Recommended to build with MinGW
  - If you just want to make a binary with gcc, there is nothing to do:
     GMP, MPFR and the program compile exactly as under Linux. (It is
     recommended to pass --build=xxx-yyy-mingw64 to the GMP configure command,
     or --build=xxx with xxx containing mingw.)

### Building

Tested with GMP 6.1.2 and MPFR 4.0.2

1. Install a 64bit compiler toolchain
  - e.g. Msys2: https://www.msys2.org/

2. Build GMP
  - Download: https://gmplib.org/#DOWNLOAD
  - gmp_install=/C/GMP_dynamic64/
  - ./configure CC="gcc -D__USE_MINGW_ANSI_STDIO" --prefix=${gmp_install} --build=haswell-pc-mingw64 --disable-static --enable-shared
    - NOTE: Not tested yet with the "CC" option, please report success/problems
    - NOTE: Might have to change haswell-pc-mingw64 to own architecture
      Should print a summary like this (+ possibly CC options):
	  Version:           GNU MP 6.1.2
	  Host type:         haswell-pc-mingw64
	  ABI:               64
	  Install prefix:    /C/GMP_dynamic64
	  Compiler:          gcc
	  Static libraries:  no
	  Shared libraries:  yes
   - make
   - make check
   - make install
   
3. Build MPFR
  - Download: https://www.mpfr.org/mpfr-current/#download
  - Also downloaded and put into extracted directory: https://www.mpfr.org/mpfr-4.0.2/allpatches
  - patch -N -Z -p1 < allpatches
  - mpfr_install=/C/MPFR_dynamic64/
  - ./configure --prefix=${mpfr_install} --with-gmp=${gmp_install} --disable-static --enable-shared
  - make
  - make install
  - make check (please report success/errors with CC option used with GMP)
    - Without the "CC" option when building GMP, this can result in errors for printf (MPFR INSTALL note: "In order to have the
    MPFR formatted output functions based on ISO-compliant printf(), you
    need to compile GMP (not MPFR) with CC="gcc -D__USE_MINGW_ANSI_STDIO"")

The DLL can then be found in the bin directory of the MPFR install directory.


## Making MPFR available for projects built with stack

For the prototype repository (similar for others):

- Copy the DLL to an extra-libs directory in the prototype repository
  - Once for runtime named "libmpfr-6.dll" (the name as produced by the compiler)
  - Once for compile time named "mpfr.dll"
- In stack.yaml:
  extra-lib-dirs: [extra-libs]
- PATH=$PATH:$PWD/extra-libs/
- Depending on terminal/setup might need to add build tools to path, e.g. for user F: PATH=$PATH:/c/Users/F/AppData/Roaming/local/bin/:/c/Users/F/.cargo/bin
- stack build Concordium
- stack test Concordium
