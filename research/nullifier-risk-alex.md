# Recovery Risk in Alex's Binary-Product Proposal

## Scope

This document analyzes Alex's binary-product idea in nullifier-specific settings.

The core product is

$$
T_A(X)=\prod_{i=0}^{m-1}(a_iX^{2^i}+b_i)
$$

If the goal is to fill an $8192$-slot spectrum with one binary product, $m=13$ is the degree-filling choice, because the product then has degree at most $8191$. In a Ragu setting, however, this is not automatically the natural choice. The nullifier can be defined as any value or relation whose derivation can be proved efficiently and soundly. Smaller $m$, larger $m$ with splitting, multiple products, product-tree commitments, bounded-exposure outputs, or extractor-based outputs are all design points.

The analysis is intentionally charitable. Alex may have been proposing a proof-friendly algebraic relation, not a complete public nullifier interface. This document therefore separates product-family structure, possible nullifier-output choices, spectrum replacement, and strengthened proof-feasible variants.

## Fairness principle

The comparison should not put the best version of the current pow5 design against the weakest possible interpretation of Alex's message.

A fair Alex-style construction may use:

- note-bound factor derivation;
- per-emitter salts;
- domain-separated keys;
- hidden query shifts;
- weighted multi-emitter mixing;
- bounded-output exposure limits.

However, any strengthened variant must remain proof-feasible. Proof feasibility should be measured against the actual current path: pow5 expansion is validated with committed polynomial identities and quotient openings, roughly sumcheck-style, rather than by naively replaying every round in the circuit. The current emitter check uses a boundary identity for round $0$ and a masked quintic recurrence identity over the whole order-$8192$ domain, with quotient-split openings at Fiat-Shamir challenges. If an Alex fix requires building a new heavy AO permutation or adding an expensive hash after every product evaluation, then it may no longer preserve the original appeal of Alex's construction.

The key question is therefore:

$$
\text{Can a proof-feasible product-like construction resist repeated public nullifier observations}
$$

## The strongest interpretation of Alex's factor claim

Alex's message appears to distinguish factor leakage from coefficient or evaluation leakage.

If the factors

$$
a_iX^{2^i}+b_i
$$

are independently sampled and remain hidden, then revealing all but one factor does not by itself reveal the last independent factor. In that narrow leakage model, the intuition is reasonable.

The protocol is free to choose what a nullifier reveals, as long as the derivation can be proved in Ragu and the public value is sufficient for duplicate-spend detection. Therefore the right question is not what nullifiers usually reveal. The right question is which public-output function is chosen and what algebraic information that function leaks.

The rest of this document distinguishes several possible public-output models:

1. factor-revealing or factor-derived outputs;
2. coefficient-derived outputs;
3. evaluation-derived outputs;
4. committed-product spectrum outputs queried through a hidden relation;
5. extracted or hashed outputs after product evaluation.

## Coefficient structure

Expanding the product gives

$$
T_A(X)=\sum_{e=0}^{2^m-1}C_eX^e
$$

Let $S(e)$ be the set of bit positions equal to $1$ in $e$. Then

$$
C_e=\prod_{i\in S(e)}a_i\prod_{i\notin S(e)}b_i
$$

If every $b_i$ is nonzero, define

$$
B=\prod_i b_i
$$

and

$$
r_i=\frac{a_i}{b_i}
$$

Then

$$
C_e=B\prod_{i\in S(e)}r_i
$$

For $m=13$, the coefficient family has $14$ effective parameters. The coefficients satisfy identities such as

$$
C_S C_T=C_{S\cap T}C_{S\cup T}
$$

Thus coefficient leakage is much more dangerous than factor leakage. A small set of well-placed coefficients can determine the whole product polynomial.

## Public-output design space

The nullifier interface can be designed. The useful comparison should therefore focus on plausible Ragu-native outputs rather than spending much space on outputs that are clearly too revealing.

The most plausible Alex-style outputs are factor-derived values, bounded transcript values, extractor-derived values, or hidden-query values derived from a committed product object. A factor-derived nullifier is closest to Alex's stated intuition: the proof can bind sparse factor polynomials into a committed product relation while the public value need not expose coefficients or repeated product evaluations.

Coefficient-derived and direct evaluation-derived outputs remain useful as cautionary boundary cases. Coefficients satisfy the compact product identities above, and repeated evaluations give equations in the small parameter set $B,r_0,\ldots,r_{m-1}$. Those output choices should not be treated as primary candidates unless a separate exposure bound or extractor argument is added.

## Strongest spectrum-replacement model

For a fair spectrum-replacement analysis, Alex's product should be paired with the strongest Ragu-feasible representation and query technique, not merely dropped into the simplest existing query.

Use $W$ independent product lanes. Each lane may correspond to an emitter, a sub-emitter, or another fixed-width query component. For lane $u$, define

$$
T_{A,u}(X)=\prod_{i=0}^{m-1}(a_{u,i}X^{2^i}+b_{u,i})
$$

The strongest representation is not a fully expanded coefficient witness as the primary object. It is a note-bound factor representation plus a split commitment to the final product. The factor parameters are pinned before the product-check challenge is derived. The final product needs

$$
s_m=\left\lceil \frac{2^m}{8192}\right\rceil
$$

capacity-wide splits. At a Fiat-Shamir challenge $z$, the proof opens those splits, recombines $T_{A,u}(z)$, and checks

$$
T_{A,u}(z)=\prod_{i=0}^{m-1}(a_{u,i}z^{2^i}+b_{u,i})
$$

This avoids exposing coefficients and avoids committing every intermediate product unless a product tree is useful for engineering reasons.

The strongest query should use the polynomial tools as design primitives, not merely reuse the existing multiplicative-coset convenience. A natural strongest benchmark is a hidden polynomial pullback. For each lane, choose a pinned hidden query map

$$
\phi_u(Y)=\sum_{r=0}^{q} h_{u,r}Y^r
$$

and define the pulled-back product

$$
U_{A,u}(Y)=T_{A,u}(\phi_u(Y))=\prod_{i=0}^{m-1}(a_{u,i}\phi_u(Y)^{2^i}+b_{u,i})
$$

The public nullifier sequence then evaluates the pulled-back products on a public geometric domain:

$$
nf_d=\sum_{u=0}^{W-1}\rho_u^dU_{A,u}(\gamma^d)
$$

Equivalently,

$$
nf_d=\sum_{u=0}^{W-1}\rho_u^d\prod_{i=0}^{m-1}(a_{u,i}\phi_u(\gamma^d)^{2^i}+b_{u,i})
$$

Only the final mixed value is public. Individual factors, coefficients, query maps, product evaluations, shifts, and weights remain hidden and proof-bound.

This model is constructible from the same polynomial utility pattern: commit to the query map and the final pulled-back product, derive a Fiat-Shamir challenge $z$, open $\phi_u(z)$ and $U_{A,u}(z)$, and check

$$
U_{A,u}(z)=\prod_{i=0}^{m-1}(a_{u,i}\phi_u(z)^{2^i}+b_{u,i})
$$

provided the factor parameters and query-map coefficients are pinned before $z$ is derived. A hidden affine coset is the degree-$1$ special case $\phi_u(Y)=\delta_u+c_uY$. The current multiplicative query is the still narrower case $\phi_u(Y)=c_uY$.

The relevant degree budget is now the pulled-back product degree

$$
\deg U_{A,u}\le q(2^m-1)
$$

so the final product needs approximately

$$
s_{m,q}=\left\lceil \frac{q2^m}{8192}\right\rceil
$$

capacity-wide splits. Under a four-split budget, the feasible frontier is roughly $q2^m\le 32768$. Examples include $m=15,q=1$, $m=14,q=2$, $m=13,q=4$, and $m=12,q=8$.

This changes the earlier interpretation of the ideal $m$. The maximum product depth remains $m=15$ for a linear pullback under a four-split budget, but the strongest query may spend some degree budget on $q$ instead of on $m$. Increasing $q$ makes the query sequence less separable and raises the recovery parameter count, while increasing $m$ preserves more of Alex's original binary-product structure.

The prediction-relevant parameter count is roughly

$$
W(2m+q+2)
$$

where $2m$ counts product factors, $q+1$ counts the hidden query map, and one additional parameter counts the geometric weight. For $W=4,m=15,q=1$, this is about $132$ parameters. For larger $q$, the count grows, but the extra dimension is coming from the hidden query map rather than from the binary product itself. If $q$ becomes large enough to dominate security, the construction has effectively added a second hidden spectrum-like object that must itself be derived and proven soundly.

This count is a nominal upper bound, not the effective dimension. The product carries per-factor scaling redundancy

$$
\prod_{i=0}^{m-1}(a_{u,i}X^{2^i}+b_{u,i})=\Big(\prod_{i=0}^{m-1}a_{u,i}\Big)\prod_{i=0}^{m-1}\Big(X^{2^i}+\tfrac{b_{u,i}}{a_{u,i}}\Big)
$$

so only the ratios $b_{u,i}/a_{u,i}$ and one overall scale are essential, and that scale folds into $\rho_u$. A pullback scale folds further into the $a_{u,i}$. The effective free-parameter count is therefore closer to

$$
W(m+q+2)
$$

For $W=4,m=13,q=4$ this is about $76$, not $128$. The reduction is the conservative direction, because fewer real unknowns make the recovery system more determined for a given number of observations.

## Concrete query-map candidates

The query map should be dense and lane-specific. A monomial map such as $\phi(Y)=cY^r$ is a poor use of the degree budget because it mainly rescales the exponents and preserves too much of the original product shape. A dense map

$$
\phi_u(Y)=h_{u,0}+h_{u,1}Y+\cdots+h_{u,q}Y^q
$$

is a better benchmark, with all coefficients derived from note-bound material and domain-separated by lane and coefficient index.

The most useful candidates under a four-split product budget are:

- $m=15,q=1$: the affine-pullback maximum-product choice. This preserves the largest binary product depth and gives one genuinely hidden affine query map per lane.
- $m=14,q=2$: a quadratic-pullback balance. This gives up one product factor to make the query nonlinear.
- $m=13,q=4$: the quartic-pullback balanced recommendation. It keeps Alex's original degree-filling product depth for an $8192$-slot spectrum while spending the extra split budget on a dense hidden query map.
- $m=12,q=8$: a query-map-heavy variant. This increases map dimension and nonlinearity, but begins shifting the security story away from Alex's product and toward the hidden map.

The largest qualitative gain arrives already at $q=1$. A hidden affine map $\phi_u(Y)=\delta_u+c_uY$ feeds the product non-geometric inputs $\delta_u+c_u\gamma^d$, which is exactly the structure the current pure-multiplicative query lacks; it is what breaks the clean $\gamma^{2^id}$ factorization that makes the multiplicative case easiest to attack. Raising $q$ beyond $1$ adds query nonlinearity with diminishing returns and trades away product depth $m$, which is Alex's distinguishing primitive. So $m=15,q=1$ is the most defensible spectrum-faithful choice, and the quartic below is best read as the balanced point where extra split budget is spent on the query rather than as a strict optimum.

A reasonable scheme to analyze next is the quartic pullback:

$$
\phi_u(Y)=h_{u,0}+h_{u,1}Y+h_{u,2}Y^2+h_{u,3}Y^3+h_{u,4}Y^4
$$

with

$$
T_{A,u}(X)=\prod_{i=0}^{12}(a_{u,i}X^{2^i}+b_{u,i})
$$

and

$$
U_{A,u}(Y)=T_{A,u}(\phi_u(Y))
$$

This has degree at most

$$
4(2^{13}-1)
$$

so it fits in four capacity-wide splits per lane. The public nullifier is

$$
nf_d=\sum_{u=0}^{W-1}\rho_u^dU_{A,u}(\gamma^d)
$$

The proof obligation is to bind $U_{A,u}$ to the pulled-back product, not to trust it as a free committed polynomial. At a Fiat-Shamir point $z$, after the factor parameters, query-map coefficients, and $U_{A,u}$ splits are committed or otherwise pinned, check

$$
U_{A,u}(z)=\prod_{i=0}^{12}(a_{u,i}\phi_u(z)^{2^i}+b_{u,i})
$$

The top query-map coefficient should be pinned nonzero if exact degree $q$ matters. Otherwise a malicious or unlucky instance with $h_{u,q}=0$ silently falls back to a lower-degree map.

The quartic map is not claimed to be a security proof. It is a fair, concrete Alex-friendly benchmark: it uses polynomial commitments, openings, split recombination, and fixed-size derived witnesses in the same spirit as the current spectrum machinery; it avoids the obviously weak pure multiplicative query; and it spends extra proof budget on query densification rather than only on increasing $m$.

## Recovery system for repeated evaluation outputs

For the strongest spectrum-replacement output model, an attacker observing pairs $(d,y_d)$ can write equations

$$
y_d-\sum_{u=0}^{W-1}\rho_u^d\prod_{i=0}^{m-1}(a_{u,i}\phi_u(\gamma^d)^{2^i}+b_{u,i})=0
$$

The affine query specializes this to $\phi_u(Y)=\delta_u+c_uY$. The cheaper multiplicative query specializes further to

$$
y_d-\sum_{u=0}^{W-1}\rho_u^d\prod_{i=0}^{m-1}(A_{u,i}\gamma^{2^id}+b_{u,i})=0
$$

where $A_{u,i}$ absorbs the hidden multiplicative shift.

Once the number of observations exceeds the effective parameter count, the system becomes overdetermined in a generic dimensional sense.

This is not a claim of a practical break as soon as observations exceed the parameter count. The equations are nonlinear, may have symmetries, may have spurious solutions, and may be difficult to solve at the target field size. The hidden-pullback version is deliberately harder than the multiplicative-coset version. The structural concern is that the attacker may still have a compact, rigid, closed-form model for the whole nullifier sequence if the chosen public-output function exposes that model repeatedly.

Additional observations can be used to reject spurious solutions and validate predictions.

## Stronger leakage cases for the spectrum model

The hidden-query spectrum model assumes only final nullifiers are public. Any stronger leakage worsens that model.

If individual lane evaluations $T_{A,u}(\phi_u(\gamma^d))$ are available, each lane becomes a separate low-dimensional recovery problem before even considering cross-lane mixing.

If coefficients of a lane product are available, the multiplicative coefficient identities can recover many other coefficients.

If $W-1$ lane contributions are isolated, the remaining contribution can be obtained by subtracting from $nf_d$.

If the hidden query maps or weights are known or attacker-controlled, the final-output system becomes more explicit.

## Proof-feasible improved uses

### Ragu-native committed product certification

The ideal proof-system application of Alex's idea should use Ragu's polynomial tools directly. Rather than proving every product evaluation as an ordinary arithmetic expression, the prover can witness note-bound factor parameters and a committed final product spectrum. Intermediate committed products are optional engineering choices, not the strongest default representation.

For one emitter, let

$$
F_i(X)=a_iX^{2^i}+b_i
$$

and certify

$$
T_A(X)=\prod_{i=0}^{m-1}F_i(X)
$$

by opening the final product splits at a Fiat-Shamir challenge and comparing the recombined value to the product of the pinned factors at the same point. This binds the final committed spectrum to the sparse product identity except with Schwartz-Zippel error. A fixed product tree is another valid implementation if it gives better locality or reuse.

The sparse shape of each factor also needs binding. A factor witness is not safe merely because it is called $a_iX^{2^i}+b_i$. The proof must pin $a_i$ and $b_i$ to note-bound material before deriving the challenge. With a compile-time fixed $m$, this is compatible with Ragu's fixed-size step model.

This is likely the best proof-feasible way to use Alex's construction as a spectrum generator. It leverages commitments and openings in the same spirit as the pow5 quotient checks. The security downside is that successful certification proves exactly that the spectrum is in the small product family, so the compact closed-form recovery analysis still applies.

### Keyed per-emitter products

The minimum fair improvement is to derive independent per-emitter product factors from note-bound key material:

$$
(a_{j,i},b_{j,i})=\mathsf{KDF}(mk,j,i)
$$

This is proof-feasible if the KDF is already available or if the factor parameters are committed and correctly constrained. It prevents global reuse of one product, but it does not remove the low-dimensional product-family structure of each emitter.

### Per-emitter salts

Per-emitter salts can domain-separate products:

$$
(a_{j,i},b_{j,i})=\mathsf{KDF}(mk,s_j,i)
$$

This is also reasonable. It strengthens independence between emitters, but the final sequence is still described by $O(N\log L)$ product parameters unless the derivation itself becomes the security-critical cryptographic expansion.

### Hidden polynomial pullbacks and weighted mixing

For spectrum replacement, the strongest proof-feasible query is a hidden mixed-output query, preferably with independent hidden polynomial pullbacks per lane. This protects against direct observation of factors, direct coefficients, and direct emitter values, and it makes the public sequence less separable than a common multiplicative shift.

The cheaper fallback is the current-style hidden multiplicative shift and weighted mixing. That fallback may match the existing proof architecture more directly, but it is not the strongest imaginable polynomial-utility query.

The residual problem is that no bounded-degree pullback erases the existence of a compact effective closed form. It changes the recovery system from a simple absorbed product in $\gamma^{2^i d}$ to a product in $\phi(\gamma^d)^{2^i}$. It still has only $O(W(m+q))$ hidden parameters for pullback degree $q$.

### Bounded-output use

Alex's construction may be more plausible if a note can emit only a bounded number of observations well below the effective parameter count. In that setting, the product could be a proof-friendly bounded-use generator.

This is a design change. It would need consensus or protocol constraints ensuring that public exposure remains below the chosen recovery margin.

## Boundary cases to keep short

Some variants are possible but should not dominate the analysis. Iterating product layers starts to become a new AO primitive requiring its own cryptanalysis and quotient-check story. Hashing after every product evaluation moves security and proof cost to the hash. Using many independent products only increases the parameter count linearly while increasing commitments and openings.

These are useful boundary cases, but the main candidate should remain a fixed-size committed product object with a carefully chosen Ragu-provable public-output function.

## Assessment

Alex's construction appears strongest when the protocol takes advantage of what Ragu can prove: sparse factors, committed product trees, factor-derived outputs, bounded-output commitments, or extractor-based public values. It is weaker specifically when the public nullifier interface becomes a long sequence of repeated product evaluations, because those observations become equations in a compact product-family parameter set.

For the spectrum-replacement design point, the fairest benchmark is keyed, salted, split-committed product lanes behind the strongest proof-feasible hidden mixed query. If hidden polynomial pullbacks of degree $q$ are feasible, the benchmark sequence is

$$
d\mapsto\sum_{u=0}^{W-1}\rho_u^d\prod_{i=0}^{m-1}(a_{u,i}\phi_u(\gamma^d)^{2^i}+b_{u,i})
$$

with roughly $W(2m+q+2)$ prediction-relevant parameters and degree budget $q2^m$. The affine query is the $q=1$ case. The current-style multiplicative hidden query is the narrowest fallback, with roughly $W(2m+1)$ prediction-relevant parameters.

The product idea should therefore not be rejected as mathematically incoherent. It should be treated as a useful proof-friendly algebraic object. Its best use may be a factor-derived or bounded-output nullifier interface rather than a drop-in long-lived evaluation sequence. As a spectrum replacement for pow5-8192, even the strongest bounded-degree hidden-pullback version has a structural recovery concern unless the added pullback degree, lane count, or extractor layer supplies a new security argument.
