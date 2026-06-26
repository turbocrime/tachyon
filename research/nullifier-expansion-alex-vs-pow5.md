# Alex Expansion vs Pow5-8192 Expansion in Isolation

## Scope

This document compares two ways to expand compact secret material into a length-$8192$ spectrum-like object before considering the outer nullifier query.

It does not analyze Alex's construction as a direct nullifier source. It also does not analyze the weighted hidden-coset query layer

$$
nf_d=\sum_j \rho_j^d T_j(c\gamma^d)
$$

Those questions are handled separately because they involve public-output leakage and proof-system binding. This document asks a narrower primitive-level question: what kind of algebraic object does each expansion rule produce?

The comparison should not be read as the strongest possible use of Alex's idea against the strongest possible use of MiMC. The bare product is analyzed first because it is the core algebraic object in Alex's message. Reasonable keyed, salted, and proof-feasible variants are then considered as possible strengthened uses.

## Pow5-8192 construction anchor

The current emitter expansion uses a pow5 MiMC-style state sequence with exponent $5$ and $8192$ rounds over the Pallas base field. The state sequence uses a cyclic expanded key schedule of length $128$.

The per-round state update is

$$
s_{r+1}=(s_r+k_{r \bmod 128}+C_r)^5
$$

The spectrum polynomial is the interpolant of the $8192$ trace states over the order-$8192$ domain:

$$
T_M(\omega^r)=s_r
$$

The interpolation step is important. The committed polynomial has $8192$ coefficients, but those coefficients are not sampled independently. They are the inverse FFT of a trace constrained by the pow5 recurrence.

## Alex's core binary product

Alex's proposed expansion has the form

$$
T_A(X)=\prod_{i=0}^{m-1}(a_iX^{2^i}+b_i)
$$

If the goal is for one binary product to fill a length-$8192$ spectrum exactly, the degree-filling choice is $m=13$, since

$$
8192=2^{13}
$$

and

$$
\sum_{i=0}^{12}2^i=8191
$$

Thus the product has degree at most $8191$, exactly fitting a length-$8192$ polynomial commitment domain.

In a Ragu setting, $m=13$ is only one design point. It is not forced by the proof system. Smaller $m$, multiple products, committed product trees, split spectra, bounded-output designs, or factor-derived public values may be better depending on the chosen nullifier interface.

The main proof-system appeal of the bare product is that its structure is easy to certify with polynomial commitments and product openings. A direct point evaluation with $m=13$ also needs only $13$ simple factors, plus the cost of deriving or witnessing the factor parameters, but direct evaluation is not the only Ragu-native use.

The present pow5 design should not be modeled as a naive circuit that spends one ordinary transition check per round. The wallet builds the trace and quotient witnesses off-circuit. Ragu validates each committed emitter by opening a small fixed set of committed polynomials at Fiat-Shamir challenges: a boundary identity pins round $0$, and a masked quintic recurrence identity checks the remaining rounds using the committed constant schedule, one opening of the committed cyclic key polynomial, and the committed quotient splits. The in-proof work is closer to sumcheck-style quotient validation than to replaying all $8192$ pow5 rounds inside the circuit.

## Ragu-feasible choices of $m$

Let the commitment capacity be

$$
L=8192=2^{13}
$$

Alex's product has degree

$$
\deg T_A \le 2^m-1
$$

A single committed spectrum therefore supports at most

$$
m=13
$$

because that is the largest $m$ with $2^m$ coefficients fitting in one capacity-wide commitment.

However, this is only the single-commitment limit. Ragu-style split openings can represent a larger committed product as adjacent capacity-wide pieces. The number of splits needed for the final product is

$$
s_m=\left\lceil \frac{2^m}{8192}\right\rceil
$$

so for $m\ge 13$ this is

$$
s_m=2^{m-13}
$$

A product identity can be checked at a Fiat-Shamir point without committing every intermediate product. Absorb the final product splits and all factor-binding material into the challenge $z$, open the final product splits at $z$, recombine $T_A(z)$, compute

$$
\prod_{i=0}^{m-1}(a_i z^{2^i}+b_i)
$$

inside the proof, and compare. The powers $z^{2^i}$ can be obtained by repeated squaring. This gives Schwartz-Zippel error about $(2^m-1)/|F|$, assuming every $a_i$ and $b_i$ is pinned before $z$ is derived.

Under that approach, the practical bound is not algebraic degree alone. It is the split count and downstream opening cost. Existing quotient-opening paths already use a handful of capacity-wide splits. Matching that scale suggests:

- $m=13$: one split, drop-in single-spectrum fit
- $m=14$: two splits, comparable to current split-lift objects
- $m=15$: four splits, comparable to the current pow5 spectrum quotient scale
- $m=16$: eight splits, plausible only as an aggressive experiment because every later query and lift also inherits the doubled opening cost
- $m>16$: likely loses the proof-cost appeal unless the public-output design avoids repeated openings of the full product

Thus the best maximum-degree candidate for a spectrum-like product that still resembles current Ragu costs is $m=15$, not $m=13$. The value $m=13$ is the maximum single-commitment choice; $m=15$ is the largest conservative split-validated choice.

This does not solve the recovery concern. With $N=4$ multiplicative-query lanes, the repeated-evaluation closed form has roughly $N(2m+1)$ prediction-relevant parameters. Increasing $m$ from $13$ to $15$ changes that count from about $108$ to about $124$, far below a long public-output budget. A stronger hidden polynomial pullback of degree $q$ raises this to roughly $N(2m+q+2)$ while consuming degree budget $q2^m$.

A fair query-map candidate is $m=13,q=4$: keep Alex's original degree-filling product depth, then spend the extra four-split budget on a dense hidden quartic map before public subgroup evaluation. This is a better benchmark than the pure multiplicative query because it uses the kind of quotient-split and domain-manipulation budget already accepted for spectrum validation.

Making the parameter count exceed $16384$ would require $m$, $q$, or the lane count to be far outside the proof-cost regime that makes the product attractive, unless the construction is no longer relying on the binary product as the main expansion primitive.

## Coefficient structure of the product

Expanding the product gives

$$
T_A(X)=\sum_{e=0}^{2^m-1} C_eX^e
$$

Let $S(e)$ be the set of bit positions equal to $1$ in the binary representation of $e$. Then

$$
C_e=\prod_{i\in S(e)}a_i\prod_{i\notin S(e)}b_i
$$

If the $b_i$ are nonzero, define

$$
B=\prod_i b_i
$$

and

$$
r_i=\frac{a_i}{b_i}
$$

Then every coefficient has the form

$$
C_e=B\prod_{i\in S(e)}r_i
$$

The apparent $8192$ coefficients are therefore constrained by only $m+1$ effective coefficient-family parameters:

$$
B,r_0,r_1,\ldots,r_{m-1}
$$

For the degree-filling example $m=13$, this is $14$ effective parameters for the nonzero coefficient family.

The coefficients also satisfy multiplicative identities. For subsets $S$ and $T$ of bit positions,

$$
C_S C_T=C_{S\cap T}C_{S\cup T}
$$

Equivalently, the base coefficient and singleton-bit coefficients determine the rest:

$$
C_S=C_\emptyset\prod_{i\in S}\frac{C_{\{i\}}}{C_\emptyset}
$$

This does not mean the construction is useless. It means the construction is a compact factorized family, not a cryptographic expansion into independent-looking amplitudes.

## Evaluation exposure caveat

Direct repeated product evaluations are not the most charitable Alex-style interface, but they are the relevant caution for spectrum replacement. A direct evaluation has the reduced form

$$
y_q=T_A(x_q)=B\prod_{i=0}^{m-1}(1+r_ix_q^{2^i})
$$

so repeated evaluations give equations in the compact parameter set. This caveat should stay short: it identifies why naive evaluation exposure is risky, not the main proposed use of the product.

## Pow5 trace structure

The pow5 expansion is also algebraic and compactly generated. It is not sampled as $8192$ independent field elements. Its difference from Alex's bare product is the use of long iterated nonlinear mixing:

$$
s_{r+1}=F_r(s_r)
$$

where

$$
F_r(x)=(x+k_{r \bmod 128}+C_r)^5
$$

Ignoring finite-field reductions, the symbolic degree in the state grows as repeated powers of $5$. After $r$ rounds, the unreduced degree scale is

$$
5^r
$$

This degree growth is not a proof of security. It is the reason MiMC-like constructions have been studied through interpolation, GCD, Gröbner-basis, and root-finding attacks rather than through simple coefficient-identity recovery.

## What the MiMC literature contributes

The relevant MiMC literature should be used as a design lens, not as a proof for Tachyon's exact use of an $8192$-round state trace.

The original MiMC paper is directly relevant because it frames interpolation and GCD attacks against low-degree iterated power maps. Later interpolation work tightens reduced-round attack analysis and reinforces that full-round parameters matter. Gröbner-basis and solving-degree analyses are relevant because they study algebraic systems arising from iterated MiMC-like maps over prime fields. Reduced-round AO root-finding work is also useful context because it shows that algebraic attacks on proof-friendly primitives are practical enough to matter.

Some references are contextual rather than directly applicable. Bonnetain's collision/key-recovery note targets Feistel-MiMC and univariate GMiMC weak key schedules; it explicitly says the attack does not appear applicable to MiMC-n/n or MiMC/GMiMC hash functions. It is therefore a key-schedule warning, not a direct break of Tachyon's pow5 emitter. The improved resultant and FreeLunch line of work primarily attacks AO permutations with low-degree inverse components under CICO modeling, especially Griffin, Arion, Anemoi, and Rescue. Those papers should not be presented as direct attacks on plain pow5 MiMC or on Alex's product unless a concrete comparable system is formulated.

## Fair Alex variants to consider

The comparison should not make Alex's construction arbitrarily unfavorable. If MiMC gets keys, salts, constants, hidden query points, and proof-system structure, then reasonable Alex variants should be considered too.

The Ragu polynomial tools also change what the ideal Alex application should look like. The best proof-system fit is not necessarily direct in-circuit evaluation of factors every time a nullifier is checked. A more Ragu-native use would certify a committed product object once, then define the public nullifier as any proof-feasible function of that object: a hidden evaluation, a factor-derived value, a bounded-use transcript value, or an extracted value.

For each emitter, define committed sparse factor polynomials

$$
F_{j,i}(X)=a_{j,i}X^{2^i}+b_{j,i}
$$

and a committed output spectrum

$$
T_{A,j}(X)=\prod_{i=0}^{m-1}F_{j,i}(X)
$$

The product relation can be certified by a fixed product tree of committed intermediate polynomials. Each product edge is checked by opening the three committed operands at a Fiat-Shamir challenge and verifying

$$
P_{u,v}(z)=P_u(z)P_v(z)
$$

Similarly, each factor's sparse shape can be checked by opening the factor at a challenge and comparing it to $a_{j,i}z^{2^i}+b_{j,i}$, provided $a_{j,i}$ and $b_{j,i}$ are already pinned to note-bound material. This uses Ragu's strengths: commitments, challenge openings, and polynomial product identities. It avoids treating Alex's construction as only a raw arithmetic gadget.

This improves the proof-cost comparison for Alex, but it does not remove the recovery concern. It soundly certifies that the committed spectrum lies in the compact binary-product family; it does not make that family cryptographically larger.

### Keyed and salted factors

A proof-feasible strengthened version would derive per-emitter factor parameters from note-bound material:

$$
(a_{j,i},b_{j,i})=\mathsf{KDF}(mk,j,i)
$$

Then each emitter could use

$$
T_{A,j}(X)=\prod_{i=0}^{m-1}(a_{j,i}X^{2^i}+b_{j,i})
$$

This avoids reusing one global product and is the minimum fair version to consider as a spectrum replacement. It does not remove the product-family identities inside each emitter. It changes how the parameters are sampled, not the effective dimension of the resulting polynomial family.

### Hidden polynomial pullbacks and weighted queries

Using Alex's product behind a hidden mixed-output query is also a fair variant. For the strongest spectrum-replacement analysis, the query should not be restricted to the cheapest multiplicative shift. Any fixed-size relation constructible from polynomial commitments, openings, products, split openings, and pinned witnesses is in scope. A natural benchmark is an independent hidden polynomial pullback and geometric weight per product lane.

That does not belong to the isolated expansion comparison itself, but it is the right benchmark to analyze in the Alex risk document. The main question is whether the outer query raises recovery cost enough while remaining proof-feasible.

### Boundary variants

Iterated product layers and hash-after-product designs are possible, but they should be treated as boundary cases. Iteration becomes a new AO primitive with its own cryptanalysis and quotient-check requirements. Hashing or extracting after each product evaluation can improve exposure behavior, but then the security and proof cost may move to the extractor.

## Proof-system feasibility filter

A strengthened Alex variant should only count as a realistic alternative if it can be handled by the proof system.

The relevant filters are:

- whether the degree fits the $8192$ commitment domain;
- how many committed factor, intermediate, and output polynomials are required;
- how many product-relation openings are needed to certify the spectrum;
- whether sparse factor shape can be constrained without making coefficients free witnesses;
- whether factor generation can be derived or constrained cheaply;
- whether hidden shifts, salts, and weights can be bound to note material;
- whether the construction remains cheap enough compared with the current pow5 quotient-opening validation path;
- what maximum product degree can be validated with a quotient-opening or sumcheck-style argument within the step budget.

Under this filter, the most plausible Alex-style use is not the bare global product evaluated ad hoc. It is a fixed-size, keyed, salted committed product object certified with product/opening relations, followed by a deliberately chosen public nullifier function. If the goal is spectrum replacement, that object should be paired with the strongest proof-feasible query: independent product lanes, hidden per-lane polynomial pullbacks if feasible, secret geometric weights, and only the final mixed output public. If higher-degree pullbacks are too costly, the fallback is a hidden affine query or the current-style multiplicative hidden shift and weighted mixing. If the goal is a different nullifier design, the public value might instead be factor-derived, bounded-use, or extractor-derived. These are separate design points and should not be collapsed into one model.

## Direct comparison in isolation

Alex's core product expansion has these properties:

- exact degree fit for $8192$ coefficients when using the degree-filling choice $m=13$;
- efficient Ragu-native certification through committed factors and product openings;
- cheap direct point evaluation when direct evaluation is the chosen interface;
- compact coefficient-family dimension for any fixed $m$;
- strong multiplicative identities among coefficients;
- a small algebraic recovery target if the chosen public-output function repeatedly exposes coefficients or evaluations;
- no established cryptographic hardness story comparable to analyzed MiMC-style recurrence.

The pow5-8192 trace expansion has these properties:

- higher prover-side witness construction cost, but efficient in-proof validation through committed quotient identities;
- compact secret material expanded through many nonlinear rounds;
- a concrete recurrence with public constants and cyclic key material;
- no analogous $14$-parameter coefficient-product identity for the interpolated spectrum;
- a security story connected to MiMC-style algebraic cryptanalysis;
- residual uncertainty because Tachyon uses a long trace as a spectrum, not just a standard MiMC final-output interface.

## Bottom line

In isolation, Alex's product is a highly proof-friendly factorized polynomial family. It is not, by itself, a cryptographic expansion comparable to a long pow5 trace.

The fair conclusion is not that Alex's idea is mathematically bad. It may be well suited to a hidden-factor leakage model, a factor-derived nullifier, a bounded-output proof-friendly commitment relation, or a committed product object used inside a larger derivation.

The concern is conditional on the public-output function. If the protocol defines a long-lived nullifier sequence as repeated product evaluations, then the public outputs create an evaluation-leakage model. In that model, the bare product exposes a compact algebraic family whose effective dimension is much smaller than the apparent spectrum length.

The strongest proof-feasible Alex variants should therefore be analyzed by public-output type: factor-derived, coefficient-derived, evaluation-derived, spectrum-replacement, bounded-use, and extractor-derived. The primitive-level fact is that the bare product has compact coefficient structure; whether that is dangerous depends on which Ragu-provable nullifier interface is selected.
