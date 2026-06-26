# Two Expansions in Isolation: Alex's Binary Product vs Pow5-8192

## What this analyzes

Both schemes expand compact secret material into a length-$8192$ polynomial before any nullifier
query is applied. This document asks the primitive-level question only: what kind of algebraic object
does each expansion produce? It does not analyze the outer query

$$
nf_d=\sum_j \rho_j^d T_j(c\gamma^d),
$$

nor public-output leakage; those belong to the interface analysis in `nullifier-risk-alex.md`, and
the budget that governs how much may be exposed is established in `surface-vs-recovery.md`.

The single fact this document establishes is the contrast in *coefficient structure*: Alex's product
is a compact factorized family with roughly $m$ free parameters, while the pow5 trace fills its
coefficients through iterated nonlinear mixing with no analogous closed form. Everything else follows
from that contrast.

## The pow5 expansion

The current emitter uses a pow5 MiMC-style state sequence with exponent $5$ over $8192$ rounds on the
Pallas base field, cycling a length-$128$ expanded key schedule:

$$
s_{r+1}=(s_r+k_{r \bmod 128}+C_r)^5.
$$

The spectrum polynomial is the interpolant of the trace states over the order-$8192$ domain,
$T_M(\omega^r)=s_r$. The committed polynomial has $8192$ coefficients, but they are not independent
samples: they are the inverse FFT of a trace constrained by the recurrence.

The proof does not replay the rounds. The wallet builds the trace and quotient witnesses off-circuit,
and Ragu certifies each emitter with a boundary identity pinning round $0$ and a masked quintic
recurrence identity over the whole domain, validated by a fixed handful of openings and quotient
splits. The in-proof cost is sumcheck-style quotient validation, not an $8192$-round circuit.

## Alex's binary product

Alex's expansion is

$$
T_A(X)=\prod_{i=0}^{m-1}(a_iX^{2^i}+b_i),\qquad \deg T_A\le 2^m-1.
$$

To fill a length-$8192$ spectrum exactly, the degree-filling choice is $m=13$, since $2^{13}=8192$
and $\sum_{i=0}^{12}2^i=8191$.

Its proof-system appeal is that the product is cheap to certify. Pin every $a_i,b_i$ to note-bound
material before deriving a Fiat-Shamir challenge $z$, open the committed product at $z$, and compare
the recombined value to $\prod_i(a_iz^{2^i}+b_i)$, with the powers $z^{2^i}$ obtained by repeated
squaring. This gives Schwartz-Zippel error about $(2^m-1)/|F|$ and needs no commitment to
intermediate products.

The degree need not stop at one commitment width. With $L=8192$ capacity, a product of degree
$2^m-1$ needs

$$
s_m=\left\lceil \frac{2^m}{8192}\right\rceil=2^{m-13}\ \ (m\ge 13)
$$

capacity-wide splits, validated by the same opening argument. Matching the split scale already
accepted elsewhere gives a practical ladder:

| $m$ | splits | comparison |
|---|---|---|
| 13 | 1 | drop-in single-spectrum fit |
| 14 | 2 | comparable to current split-lift objects |
| 15 | 4 | comparable to the current pow5 spectrum quotient scale |
| 16 | 8 | aggressive; every later query and lift inherits the doubled opening cost |

So the largest conservative split-validated depth is $m=15$, while $m=13$ is the maximum
single-commitment choice. Higher $m$ loses the proof-cost appeal unless the public output avoids
repeated openings of the full product. (Whether more depth buys security is a query-interface
question, deferred to `nullifier-risk-alex.md`.)

## Coefficient structure of the product

This is the heart of the comparison and the result the interface analysis relies on.

Expanding the product, index each coefficient by the bit positions $S(e)$ set in $e$:

$$
T_A(X)=\sum_{e=0}^{2^m-1}C_eX^e,\qquad C_e=\prod_{i\in S(e)}a_i\prod_{i\notin S(e)}b_i.
$$

If the $b_i$ are nonzero, set $B=\prod_i b_i$ and $r_i=a_i/b_i$. Then every coefficient is a single
monomial in the ratios:

$$
C_e=B\prod_{i\in S(e)}r_i.
$$

So the apparent $8192$ coefficients are governed by only $m+1$ parameters $B,r_0,\ldots,r_{m-1}$;
for $m=13$, that is $14$. Equivalently the coefficients obey the multiplicative identities

$$
C_S C_T=C_{S\cap T}\,C_{S\cup T},\qquad C_S=C_\emptyset\prod_{i\in S}\frac{C_{\{i\}}}{C_\emptyset},
$$

so the base and singleton-bit coefficients determine all the rest. The construction is a compact
factorized family, not an expansion into independent-looking amplitudes.

The same compactness shows up under direct evaluation, which is why repeated raw evaluations are
the cautionary interface: a single evaluation reduces to

$$
T_A(x)=B\prod_{i=0}^{m-1}(1+r_ix^{2^i}),
$$

an equation in the same $m+1$ parameters.

## Pow5 trace structure

The pow5 trace is also compactly generated and is not $8192$ independent field elements. The
difference is iterated nonlinear mixing:

$$
s_{r+1}=F_r(s_r),\qquad F_r(x)=(x+k_{r\bmod 128}+C_r)^5.
$$

Ignoring field reduction, the symbolic degree in the state grows as $5^r$. This degree growth is not
itself a security proof, but it is why MiMC-like constructions are studied through interpolation,
GCD, Gröbner-basis, and root-finding attacks rather than through coefficient-identity recovery. There
is no $14$-parameter product identity for the interpolated trace. The relevant cryptanalytic
evidence, and its limits for the trace-as-spectrum interface, is collected in `mimc-handoff.md` and
summarized in `nullifier-risk-current.md`; it is not repeated here.

## Direct comparison

Alex's product, in isolation:

- exact degree fit for $8192$ coefficients at $m=13$, and cheap Ragu-native certification through
  factor pinning and a product opening;
- compact coefficient-family dimension ($m+1$ parameters) for any fixed $m$, with strong
  multiplicative identities among coefficients;
- a small algebraic recovery target whenever the public output exposes coefficients or evaluations;
- no established hardness story comparable to analyzed MiMC-style recurrences.

The pow5-8192 trace, in isolation:

- higher prover-side witness cost, but efficient in-proof validation through committed quotient
  identities;
- compact secret material expanded through many nonlinear rounds, with no analogous low-parameter
  coefficient identity;
- a security story connected to MiMC algebraic cryptanalysis, with one residual
  construction-specific assumption (a long trace used as a spectrum, not a standard MiMC output).

## Bottom line

In isolation, Alex's product is a highly proof-friendly factorized polynomial family; it is not, by
itself, a cryptographic expansion comparable to a long pow5 trace. This does not make the idea bad.
It makes the product a good fit for uses that do not repeatedly expose its compact structure, and a
poor fit as a drop-in long-lived evaluation spectrum. Which of those it is depends entirely on the
nullifier interface, analyzed next in `nullifier-risk-alex.md`.
