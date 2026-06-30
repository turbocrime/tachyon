# Handoff: empirical round-count floor for a MiMC-based nullifier

A self-contained brief for an implementing agent. It states the problem and lays out the
option space. **It does not pick an attack, solver, or hardware target. Those are the
implementing agent's decisions.** The recipient needs no prior context.

This is the MiMC counterpart to the binary-product attack handoff, but its *purpose is
different*. The product is broken and the demo proves it. MiMC is the standard hardness an
arithmetization-oriented nullifier rests on, so the deliverable here is **not a break**: it is
the **round-count floor**, the number of rounds `r` at which each known attack crosses from
feasible to infeasible, measured on real hardware and extrapolated to a target security level.
That floor is the open question (the scheme's own "how large must `r` be" TODO).

## Scenario

A candidate nullifier derivation is a keyed MiMC permutation evaluated at the epoch:

```
nf_e = E_k(e),   E_k(x) = k + (F_{r-1} o ... o F_0)(x),   F_i(x) = (x + k + c_i)^5
```

- `k = PRF_nk(psi)` is the only secret. The round constants `c_i` are public (fixed at
  setup). The same key `k` is injected each round (classic MiMC key schedule).
- Field: **Pallas base field** `F_p` (Pasta), `p ~ 2^254`. Exponent `alpha = 5`
  (`gcd(5, p-1) = 1` on Pasta). The polynomial degree of `E_k` in the input grows as `5^r`
  and saturates near `p` at `r ~ log_5 p ~ 110`.
- Target epoch space `L` (e.g. `2^13 = 8192` or `2^14 = 16384`); epochs are public, positive,
  sequential, starting at any nonzero offset.
- Variants worth keeping in mind but not the primary target: key injected only at start/end,
  or the **trace-as-spectrum** construction (`nf_d = sum_j rho_j^d T_j(c gamma^d)`, weighted
  samples of an 8192-round trace interpolant). The spectrum is a separate, harder target
  because it additionally exposes known linear functionals of the full internal trace; note it
  and move on unless asked.

## Problem

Given `(e, nf_e)` for a window of known epochs, either **recover `k`** (which yields every
nullifier) or **distinguish `nf_e` from random** at an unqueried epoch (the scheme's actual
security bar is indistinguishability, which is strictly stronger than non-recoverability).
Measure the cost of each attack as a function of `r`, find where it crosses from feasible to
infeasible on the available hardware, and extrapolate to a chosen security level (e.g.
`2^128`). The output is a recommended minimum `r` with margin.

Contrast with the product handoff: there the structure makes recovery a low-degree solve that
*succeeds*. Here the degree growth `5^r` is the defense, so the attacks are expected to *fail*
beyond some `r`, and the experiment is to locate that `r`.

## Demonstration targets

Sweep the round count `r` (e.g. `r in {2, 4, 6, 8, 10, 12, 14, 16, ...}` up to where each
attack stops finishing) and, for each attack family, record the wall-clock / memory and the
feasibility crossover. The headline deliverables:

- a cost-vs-`r` curve per attack family,
- the largest `r` broken on each machine,
- an extrapolated minimum `r` for the target security level and epoch space,
- for any successful run: recovered `k` (or a working distinguisher) plus a correctly predicted
  `nf` at an unqueried epoch, as proof.

## Attack families (options, established MiMC cryptanalysis)

- **GCD key recovery** (cheapest in data; needs only two pairs). For pairs `(e1, nf1)`,
  `(e2, nf2)`, form `P_j(K) = E_K(e_j) - nf_j in F_p[K]`, each of degree `5^r` in the unknown
  key `K`; the true `k` is a common root, so `gcd(P1, P2)` reveals it (generically linear).
  Cost and memory `~Otilde(5^r)`; the naive form stores a degree-`5^r` polynomial
  (`5^r` field elements). This is typically the primary round-count constraint; the crossover
  is roughly where `5^r` exceeds feasible storage/compute.
- **Interpolation / integral (higher-order differential) distinguisher** (needs many pairs).
  With a window `W > 5^r` of known epochs you can interpolate the degree-`5^r` map
  `e -> nf_e` and then predict any `nf` (a clone, no key needed); equivalently the
  `(5^r + 1)`-th finite difference over consecutive epochs vanishes, giving a distinguisher.
  Only bites while `5^r < W`, so it constrains only small `r`.
- **Gröbner basis with intermediate round variables** (the modern attack; likely the binding
  constraint near the floor). Introduce a variable per round per pair, `x_{j,i+1} =
  (x_{j,i} + k + c_i)^5` (degree 5), with `nf_j = x_{j,r} + k`; solve the degree-5 system for
  `k`. Complexity is governed by the solving degree / degree of regularity; the linear-algebra
  core is the cost. Full-round key-recovery results exist (faster than brute force) and should
  anchor the extrapolation.

## Solver and hardware options (tradeoffs, for the implementer to choose)

- **NTT-based polynomial arithmetic** (for GCD and interpolation): building the degree-`5^r`
  polynomial via repeated `(.)^5` composition, and the GCD/interpolation themselves, are fast
  polynomial multiply / multipoint operations over `F_p`. This is the route where a GPU helps
  most, and Pasta NTT is available off the shelf (ICICLE). Storage of the degree-`5^r`
  polynomial is the wall (favoring the 128 GB box); storage-optimized multipoint variants
  trade memory for time.
- **Gröbner** (msolve, Magma) for the intermediate-variable system; CPU-bound, or hand-roll
  XL/Macaulay and put the `GF(p)` linear algebra on a GPU.
- **Integral/higher-order sums**: embarrassingly parallel, trivially GPU- or CPU-friendly.
- **Not applicable**: numerical / homotopy methods (exact algebra over a finite field).

## Environment / operator notes

- Available hardware: a Framework desktop (128 GB RAM, the implementing machine) and an M3
  MacBook Pro (36 GB, the developer's machine). The large-RAM box favors the GCD storage wall;
  a GPU favors NTT polynomial arithmetic and the Gröbner/XL linear-algebra core.
- The operator prefers a GPU-first approach where it offers a real benefit. For this target
  that benefit is more concrete than for the product, because GCD/interpolation are NTT-bound
  and ICICLE ships Pasta NTT on CUDA. The choice of method remains the implementing agent's.

## Sanity ladder

1. Tiny `r` (e.g. `r = 2`) — confirm the rig recovers `k` by GCD from two pairs and predicts an
   unqueried `nf`.
2. Low `r` with a wide window — confirm interpolation/integral cloning works while `5^r < W`.
3. Sweep `r` upward with GCD and Gröbner until each stops finishing; record the crossover and
   the cost-vs-`r` slope, then extrapolate.

## Success metric

A cost-vs-`r` curve for each attack family on a single machine, the largest `r` actually
broken, and an extrapolated minimum `r` (with margin) for the target epoch space and security
level. A recovered `k` or working distinguisher at any `r`, with a correctly predicted
unqueried `nf`, is the proof of break for that `r`. The end product answers "how many rounds
does the MiMC nullifier need," empirically rather than by quoting `log_5 p`.

## References

- Albrecht, Grassi, Rechberger, Schofnegger, Tiessen, *MiMC: Efficient Encryption and
  Cryptographic Hashing with Minimal Multiplicative Complexity*, ASIACRYPT 2016 — the
  construction and the original interpolation/GCD round-count argument (`r = ceil(log_5 p)`).
- Eichlseder, Grassi, Lüftenegger, Øygarden, Rechberger, Schofnegger, Wang, *An Algebraic
  Attack on Ciphers with Low-Degree Round Functions: Application to Full MiMC*, ASIACRYPT 2020
  — full-round key recovery faster than brute force; anchors the extrapolation.
- Bariant et al., *The Algebraic FreeLunch: Efficient Gröbner Basis Attacks Against
  Arithmetization-Oriented Primitives*, CRYPTO 2024 — modern Gröbner attacks on AO designs.
- Jakobsen & Knudsen, *The Interpolation Attack on Block Ciphers*, FSE 1997.
- Zellic, *Algebraic Attacks on ZK-Friendly Hash Functions*
  (https://www.zellic.io/blog/algebraic-attacks-on-zk-hash-functions/) — practitioner walkthrough
  of interpolation and Gröbner-with-intermediate-variables on MiMC-family ciphers.
- Tools: ICICLE (Ingonyama, GPU Pasta NTT/MSM), FLINT / NTL (polynomial GCD and interpolation
  over `F_p`), msolve and Magma (Gröbner).

## One-line framing

"For `nf_e = MiMC_k(e)` over the Pallas base field with exponent 5, given known
epoch/nullifier pairs, run the standard MiMC attacks (GCD key recovery from two pairs;
interpolation/integral cloning while `5^r < W`; Gröbner over the intermediate-round system)
across a sweep of round counts `r`, measure where each stops being feasible on the available
hardware, and report the extrapolated minimum `r` for the target epoch space and security
level. The deliverable is a round-count floor, not a break."
