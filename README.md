### `Details`

- This repository contains the C reference implementation for my research paper currently under development.

- It implements the M-Schnorr identification protocol over a high-dimensional torus variety and provides a lattice-based signature prototype in the style of Lyubashevsky, utilizing rejection sampling.

### `Building from source`

- Compilation requires a C99 compiler and linkage with the math library. On most 64‑bit Unix‑like systems, GCC or Clang will automatically detect the __uint128_t extension.


          gcc -std=c99 -O3 -march=native -o manifold_zkp manifold_zkp.c -lm

- Windows builds with Visual Studio can use the command‑line compiler directly, as the preprocessor will switch to the intrinsic path.

          cl /O2 /Fe:manifold_zkp.exe manifold_zkp.c

- No additional libraries are needed. The SHA‑3 implementation, the Keccak‑f[1600]f[1600] permutation, and all protocol logic are self‑contained.


### `Interpreting the output`

- results.json captures the completeness rate (expected near 1), the empirical soundness advantage (the fraction of forgeries that succeeded against a random challenge; ideally of the order 2^{-32} or lower in the interactive setting), and the zero knowledge advantage as one minus the success rate of simulated transcripts.

- The three attack‑cost fields are rough scaling heuristics that appear in the paper’s security discussion; they should not be taken as formal bit‑security claims. The benchmark entry lists the C implementation’s timing on the host machine.

### `Limitations`

- The M‑Schnorr protocol is kept in its interactive form and has not been transformed into a non interactive signature via Fiat–Shamir.
  
- The Lyubashevsky scheme compiles but has not been verified for correctness or parameter safety; it should be treated as an algorithmic sketch rather than a production‑ready construction.

- On Linux, the random source may block when entropy is low, while Windows rand_s always returns immediately. The attack cost formulas serve as scaling heuristics and should not replace a formal security estimation for production parameters.
