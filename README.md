# elliptic_cpp_int
`elliptic_cpp_int` exercises and exemplifies elliptic curve geometrical calculations. Big-integer machematics is carried out with arbitrary precision `cpp_int` from `Boost.Multiprecision`.

## Calculation descriptions

ECDSA mathematics with arbitrary precision signed big integers is carried out in order to to create key-pairs,
sign and verify a selected predefined and various random messages using the `secp256k1` curve.

In the first test, one predefined message is signed and verified.
The program continues to sign and verify 10 random messages
and also to verify intended failure of a test case that is expected to fail.

The arbitrary precision signed integer type `cpp_int` from `Booost.Multiprecision` is used
for internal big integer calculations.

## Notes

This program is not intended for applicability nor for speed or performance.
Rather, it is supposed to help visualize the beautiful mathematics
of elliptic curve geometry and large-integer mathematics.

## Mathematical background

TBD: Show algorithms such as inverse-modulus, scalar-multiplication etc.

## Environments and CI

The program has been tested with `C++20` on MSCV, GCC and clang.
A skinny CI running tests is included and supports GCC and clang.
