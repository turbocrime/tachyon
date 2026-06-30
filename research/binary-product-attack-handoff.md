# Handoff: empirical attack on a binary-product nullifier derivation

A self-contained brief for an implementing agent. It states the problem and lays out the
option space. **It does not pick a formulation, solver, or hardware target. Those are the
implementing agent's decisions.** The recipient needs no prior context.

## Scenario

A proposed nullifier scheme derives a note's per-epoch nullifier as the evaluation of a
secret polynomial:

```
nf_e = f(e),    f(X) = prod_{i=0}^{n-1} (a_i * X^(2^i) + b_i)
```

- `n` = number of factors. Target instances: **`n = 13` (lifetime `L = 2^13 = 8192`)** and
  `n = 14` (`L = 16384`).
- `deg f = 2^n - 1`, so the epoch domain is `e in {0, ..., L-1}`.
- Field: **Pallas base field** `F_p` (Pasta)
- Secrets `a_i, b_i` are nonzero field elements (PRF-derived in the real scheme; sample
  uniformly for the demo). Normalize: `f(X) = B * prod_i (1 + r_i X^(2^i))` with
  `B = prod b_i`, `r_i = a_i / b_i`. So `f` is determined by the **`n+1` values
  `(B, r_0, ..., r_{n-1})`** (14 for `n=13`). Every coefficient is a subset product:
  `C_e = B * prod_{i in S(e)} r_i`, where `S(e)` is the set bits of `e`.

## Problem

The attacker (a delegated sync service) is given `nf_e` for a window of `W`
consecutive positive epochs `e in {e0, ..., e0+W-1}`. The offset `e0` begins at
**any nonzero value** (notes never start at epoch 0; epochs are positive and
sequential). The attack must not depend on `e0`, recovery should succeed for an
arbitrary nonzero offset.

Recover `(B, r_i)`, then predict `nf_{e*}` at an epoch `e*` *outside the
window*. (e.g. the would-be spend epoch `L-1`) and verify it equals `f(e*)`.
Report wall-clock.

Why small `W` is the interesting case: any `W < L = deg(f)+1` makes Lagrange
interpolation of `f` impossible (and no coefficient can be read off, a sub-full
point set aliases high-degree terms into low ones), so the attack is forced
onto the `(n+1)`-parameter structure rather than the trivial
interpolate-and-factor route.

## Demonstration targets

Show recovery and timing at **revealed-window sizes `W in {64, 128, 256, 512,
1024, 2048, 4096}`** (all far above the `n+1 = 14` information-theoretic
minimum, and all far below `L`, so each one forces the structured solve). For
each `W`:

- use an arbitrary nonzero `e0` (ideally repeat with two different offsets to confirm the
  result is offset-independent),
- recover `(B, r_i)`,
- predict `nf` at one or more unrevealed epochs (e.g. `L-1`) and verify equality,
- record wall-clock.

The headline result is the recover/verify outcome and the runtime-vs-`W` curve across those
four windows.

## Reductions (options, not a recommendation)

### A. Small variable count (`n` unknowns)

Eliminate `B` by dividing pairs of nullifiers, leaving `n` unknowns `r_i` and `W-1`
equations:

```
prod_i (1 + r_i * e_j^(2^i)) * nf_{e0}  =  prod_i (1 + r_i * e0^(2^i)) * nf_{e_j}
```

Each is multilinear (degree 1 in each `r_i`, total degree `n`); the system is over-determined.
Recover `B` from any single nullifier afterward. Note: linearizing this at native degree is
equivalent to interpolation and needs `2^n` equations, which the small `W` denies, so this
formulation is not closed by plain linearization.

### B. Coefficient variety (`2^n` sparse unknowns)

Unknowns: the `2^n` normalized coefficients `c_e = C_e / B`. Constraints: `W-1` linear
Vandermonde cuts `sum_e c_e * e_j^e = nf_{e_j}/B` (work projectively or fix one `c` to absorb
`B`), plus the sparse quadratic multiplicative relations `c_S * c_T = c_{S∩T} * c_{S∪T}` that
pin `c` to the rank-`(n+1)` subset-product variety. Over-determined sparse quadratic system.

Both reductions describe the same recovery; they differ in variable count vs sparsity and
therefore in which solver class fits.

## Solver and hardware options (tradeoffs, for the implementer to choose)

- **Gröbner basis** (msolve, Magma): strongest general tooling, natural fit for reduction A;
  CPU-bound. Over-determination tends to keep the solving degree low; FGLM is worst-case
  `~n!` but heavily pruned by the extra equations.
- **XL / Macaulay linearization** (natural fit for reduction B): reduces to `GF(p)` linear
  algebra, dense at small XL degree, sparse at large. This is the route on which a GPU can
  help.
- **Sparse `GF(p)` linear algebra** (block Wiedemann / block Lanczos): for large sparse XL
  systems; dominated by sparse mat-vec over `GF(p)`, which is GPU-friendly; the same toolkit
  used for factoring / discrete-log linear algebra.
- **GPU consideration:** a GPU accelerates the linear-algebra core of the XL / sparse route,
  not classic Gröbner (which is CPU). At `n=13` the solve may be small enough that a CPU
  Gröbner run settles it, in which case GPU benefit is marginal; the GPU payoff grows with
  `n` and with solving degree / matrix size. A 254-bit field kernel is required: ICICLE
  (Ingonyama) ships Pasta field/NTT/MSM on CUDA and can be built on, or wrap a CUDA `GF(p)`
  routine.
- **Not applicable:** numerical / homotopy continuation. This is exact algebra over a finite
  field.

## Environment / operator notes

Available hardware
- a Framework desktop 128 GB RAM, your present machine.
- an M3 MacBook Pro 36 GB, the developer's machine. 

The operator prefers a GPU-first approach **where it offers a real benefit**
but leaves the choice of method to the implementing agent.

## Sanity ladder

1. `n=3`, full window — confirm the rig recovers `(B, r_i)` and predicts an unseen `nf`.
3. `n=13`, full `W = 8192` — interpolate-and-factor; fast, proves the pipeline end to end.
4. `n=13`, `W in {64, 128, 256, 512}` — the demonstration (structured solve, arbitrary `e0`).

## Success metric

For each demonstration window: recovered `(B, r_i)` from `W` consecutive nullifiers at an
arbitrary nonzero `e0`, a correctly predicted `nf` at an unrevealed epoch, and a wall-clock
number, on a single machine. The predicted-unrevealed-nullifier check is what demonstrates
the break.

## References

- Naor & Reingold, *Number-Theoretic Constructions of Efficient Pseudo-Random Functions*,
  JACM 2004 — `f`'s coefficients realize the NR subset product, which is pseudorandom only
  behind a one-way (DDH/factoring) wrapper this scheme lacks.
  https://static.aminer.org/pdf/PDF/000/951/256/number_theoretic_constructions_of_efficient_pseudo_random_functions.pdf
- Klivans & Shpilka, *Learning Restricted Models of Arithmetic Circuits* — products/sums of
  linear forms are reconstructible from evaluations.
  https://www.cs.tau.ac.il/~shpilka/publications/KlivansShpilka_Learning_via_partial_derivatives.pdf
- Volkovich, *A Guide to Learning Arithmetic Circuits*, COLT 2016.
  http://proceedings.mlr.press/v49/volkovich16.pdf
- *Reconstruction Algorithms for Low-Rank Tensors and Depth-3 Multilinear Circuits*,
  arXiv:2105.01751.
- Jakobsen & Knudsen, *The Interpolation Attack on Block Ciphers*, FSE 1997.
- Albrecht, Cid, Grassi, Khovratovich et al., algebraic cryptanalysis of MiMC / Jarvis /
  STARK-friendly designs; Zellic, *Algebraic Attacks on ZK-Friendly Hash Functions*
  (https://www.zellic.io/blog/algebraic-attacks-on-zk-hash-functions/) — high degree from few
  parameters is weak; intermediate variables collapse the Gröbner cost.
- Ben-Or & Tiwari, sparse polynomial interpolation.
- Tools: msolve (Berthomieu–Eder–Safey El Din), Magma, ICICLE (Ingonyama, GPU Pasta).

## One-line framing

"Given a window of consecutive evaluations of `f(X) = prod_{i<13}(a_i X^(2^i)+b_i)` over the
Pallas base field, at any nonzero starting epoch, recover the 14 secrets and predict an
unrevealed `nf`. It reduces to either an over-determined multilinear system (13 vars) or a
sparse structured quadratic system (`2^13` coeffs); the implementer chooses the formulation,
solver, and hardware. Demonstrate at windows of 64, 128, 256, and 512 and report wall-clock
plus a correct unrevealed-nullifier prediction."

