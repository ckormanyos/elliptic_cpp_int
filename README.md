elliptic_cpp_int
==================

<p align="center">
    <a href="https://godbolt.org/z/se8jGqv31" alt="godbolt">
        <img src="https://img.shields.io/badge/try%20it%20on-godbolt-green" /></a>
</p>

`elliptic_cpp_int` exercises and exemplifies elliptic curve geometrical calculations. Big-integer machematics utilizes arbitrary precision `cpp_int` from `Boost.Multiprecision`.

Support for the project [eisenwave/std-big-int](https://github.com/eisenwave/std-big-int) has been integrated, providing for an optional test of this big-integer type in the demanding domain of elliptic curve geometrical calculations.

It is also possible to configure the use of `gmp_int` from `Boost.Multiprecision`.

Selecting the big integer type:
  - To use `cpp_int` from `Boost.Multiprecision`, define nothing on the complier command line nor in the code.
  - To use [eisenwave/std-big-int](https://github.com/eisenwave/std-big-int), define `ELLIPTIC_CPP_INT_USE_STD_BIG_INT` either on the complier command line or in the location in the code itself.
  - To use `gmp_int` from `Boost.Multiprecision`, define `ELLIPTIC_CPP_INT_USE_GMP_INT` either on the complier command line or in the location in the code itself.

## Application descriptions

ECDSA mathematics with arbitrary precision signed big integers is carried out in order to to create key-pairs,
sign and verify a selected predefined and various random messages using the `secp256k1` curve.

In the first test, one predefined message is signed and verified.
The program continues to sign and verify 10 random messages
and also to verify the _intended_ failure of a test case that is, by design,
expected to fail.

The arbitrary precision signed integer type `cpp_int` from `Booost.Multiprecision` is used
for internal big integer calculations or the alternate big integer types, as mentioned above.

## Notes

This program is not intended for applicability nor for speed or performance.
Rather, it is supposed to help visualize the beautiful mathematics
of elliptic curve geometry and large-integer mathematics.

## Mathematical background

TBD: Show algorithms such as inverse-modulus, scalar-multiplication etc.

## Environments and CI

The program has been tested with `C++23`.
A skinny CI running tests is included and supports GCC and clang.
