# Alex's Expansion in Isolation vs MiMC-like Pow5 Expansion

## Scope

This note compares two ways to expand compact secret material into a length-$L$ spectrum polynomial.

Alex's binary-product expansion is

$$
T_A(X)=\prod_{i=0}^{m-1}(a_iX^{2^i}+b_i)
$$

The MiMC-like pow5 expansion is a trace recurrence

$$
s_{r+1}=(s_r+k_{r+1}+C_{r+1})^5
$$

with the spectrum polynomial defined by interpolation from the trace values

$$
T_M(\omega^r)=s_r
$$

The comparison focuses only on the expansion rule: how much independent-looking structure the rule creates, how compactly the resulting spectrum can be described, and what kind of recovery target it presents.

## What expansion is supposed to provide

The expansion goal is not merely to fill a degree-$L-1$ polynomial. It is to turn compact secret material into a long spectrum whose values and coefficients do not admit a small, attacker-useful algebraic description.

For the target spectrum length

$$
L=8192=2^{13}
$$

a good expansion should make the resulting spectrum look more like a cryptographic trace or pseudorandom sequence than like a polynomial family with only $O(\log L)$ effective parameters.

## Alex's binary-product expansion

Alex's proposed spectrum has the form

$$
T_A(X)=\prod_{i=0}^{m-1}(a_iX^{2^i}+b_i)
$$

For $L=8192$, the required number of factors is

$$
m=13
$$

because

$$
\sum_{i=0}^{m-1}2^i=2^m-1=8191
$$

This exactly covers the exponent range from $0$ to $L-1$. The binary decomposition of an exponent determines which factor contributes its $a_iX^{2^i}$ term and which factor contributes its $b_i$ term.

That exact binary decomposition is also the structural weakness.

## Alex's effective dimension as a polynomial family

Expand one binary-product spectrum:

$$
T_A(X)=\sum_{e=0}^{2^m-1} C_eX^e
$$

Let $S(e)$ be the set of bit positions equal to $1$ in the binary representation of $e$. Then

$$
C_e=\prod_{i\in S(e)}a_i\prod_{i\notin S(e)}b_i
$$

For nonzero $b_i$, define

$$
B=\prod_i b_i
\qquad
r_i=\frac{a_i}{b_i}
$$

Then every coefficient is

$$
C_e=B\prod_{i\in S(e)}r_i
$$

So the entire length-$2^m$ coefficient vector is determined by only

$$
m+1
$$

effective polynomial parameters:

$$
B
\qquad
r_0
\qquad
r_1
\qquad
\ldots
\qquad
r_{m-1}
$$

For $m=13$, this is only

$$
14
$$

effective parameters for the polynomial itself.

Counting the original factor variables gives $2m=26$ symbols, but this overcounts the polynomial family. Rescaling individual factors while preserving the product scale does not change $T_A$. The coefficient formula gives the smaller effective dimension that matters for recovery of the expanded polynomial.

## Coefficient identities

The coefficients of Alex's expansion satisfy simple multiplicative identities. For subsets $S$ and $T$ of bit positions,

$$
C_SC_T=C_{S\cap T}C_{S\cup T}
$$

The coefficients are therefore not independent amplitudes. The base coefficient and the singleton-bit coefficients determine the remaining coefficients:

$$
C_S=C_\emptyset\prod_{i\in S}\frac{C_{\{i\}}}{C_\emptyset}
$$

This is a direct entropy collapse at the expansion layer. The construction appears to create $2^m$ coefficients, but those coefficients lie on an $(m+1)$-dimensional multiplicative variety.

## Evaluation equations in isolation

Direct evaluations of Alex's expansion have the reduced form

$$
y_q=T_A(x_q)=B\prod_{i=0}^{m-1}(1+r_ix_q^{2^i})
$$

Each evaluation gives one equation in the $m+1$ effective unknowns $B,r_0,\ldots,r_{m-1}$. This is a nonlinear system, not ordinary polynomial interpolation. The important point is dimensional: the algebraic target has only $m+1$ effective unknowns.

For $m=13$, the isolated algebraic-recovery target is therefore on the order of

$$
14
$$

effective unknowns, not $8192$ independent amplitudes.

The attacker is not facing an arbitrary length-$8192$ spectrum. The attacker is facing a $14$-parameter family.

## MiMC-like pow5 expansion

A MiMC-like pow5 expansion produces a trace through repeated nonlinear rounds:

$$
s_{r+1}=(s_r+k_{r+1}+C_{r+1})^5
$$

In isolation, the spectrum is the interpolation of the trace:

$$
T_M(\omega^r)=s_r
$$

Unlike Alex's product, the trace is not defined by independently selecting a small set of coefficient ratios. Each state is recursively dependent on previous states, round keys, and round constants.

## Algebraic shape of pow5 expansion

Ignoring finite-field degree reductions, repeated pow5 rounds grow algebraic degree rapidly. After one round, the state is degree $5$ in its input expression. After two rounds, the nested expression has degree roughly

$$
5^2
$$

After $r$ rounds, the unreduced symbolic degree is roughly

$$
5^r
$$

This degree growth is not by itself a proof of security. The field is finite, the key schedule may be structured, and the recurrence is algebraic. But it is a qualitatively different structure from Alex's product family.

Alex's expansion separates by binary exponent bits:

$$
C_e=B\prod_{i\in S(e)}r_i
$$

The pow5 trace repeatedly feeds the whole previous state into the next nonlinear round:

$$
s_{r+1}=F_r(s_r)
$$

where

$$
F_r(x)=(x+k_{r+1}+C_{r+1})^5
$$

That recurrence is intended to provide avalanche and cryptographic mixing. Alex's product provides exact coefficient coverage, but not comparable mixing.

## Proof-cost comparison

Alex's construction is attractive in a proof system because a product of $m$ simple factors is cheap to evaluate at a point. For $L=8192$, proving or checking a point evaluation of

$$
\prod_{i=0}^{12}(a_iX^{2^i}+b_i)
$$

is much cheaper than certifying thousands of pow5 rounds.

The MiMC-like pow5 expansion is more expensive because the proof must enforce the recurrence across the trace domain:

$$
s_{r+1}=(s_r+k_{r+1}+C_{r+1})^5
$$

That cost buys a different security story. The pow5 expansion attempts to replace a low-dimensional algebraic product with a cryptographic permutation-style recurrence.

The tradeoff is therefore not simply binary exponentiation versus fifth powers. It is cheap algebraic expandability versus expensive cryptographic mixing.

## Direct comparison

Alex's isolated expansion has these properties:

- very cheap arithmetic structure;
- exact coverage of all exponents $0$ through $2^m-1$;
- only $m+1$ effective polynomial parameters in the nonzero case;
- strong multiplicative identities among coefficients;
- an isolated recovery target with roughly $m+1$ effective unknowns;
- no clear cryptographic hardness assumption beyond solving a small algebraic system.

The MiMC-like pow5 expansion has these properties:

- much higher proving cost;
- compact secret input expanded through many nonlinear rounds;
- no obvious $m+1$-parameter coefficient identity for the resulting interpolated spectrum;
- security that depends on concrete cryptanalysis of the MiMC-style recurrence;
- a cryptographic mixing story based on repeated nonlinear state updates.

## Bottom line

Considered in isolation, Alex's expansion is not a cryptographic expansion. It is a compact algebraic parameterization of a long polynomial:

$$
T_A(X)=B\prod_{i=0}^{m-1}(1+r_iX^{2^i})
$$

For $L=8192$, this gives only $14$ effective polynomial parameters. The construction fills $8192$ coefficient slots, but it does not create $8192$ independent-looking amplitudes.

The MiMC-like pow5 expansion is more expensive and still assumption-based, but it has the right shape for cryptographic expansion: repeated nonlinear mixing with pinned constants and key material. It does not reduce to a simple binary-coordinate coefficient product.

For an isolated spectrum generator, Alex's product expansion is easier to prove but structurally much weaker. The MiMC-like pow5 expansion is harder to prove but offers a plausible cryptographic expansion story.
