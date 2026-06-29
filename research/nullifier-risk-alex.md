# Alex's Binary Product as a Nullifier Interface

## What this analyzes

`nullifier-expansion-alex-vs-pow5.md` established the primitive: Alex's product
$T_A(X)=\prod_{i=0}^{m-1}(a_iX^{2^i}+b_i)$ is a compact factorized family whose $2^m$ coefficients
$C_e=B\prod_{i\in S(e)}r_i$ are governed by only $m+1$ parameters. This document takes that as given
and asks the interface question: when a nullifier is *built* from the product and published, what
does it leak, and can any proof-feasible construction make a long-lived nullifier sequence resist
recovery?

Alex's stated proposal is the simpler direct evaluation $nf_e=f(e)$, whose first question is binding
rather than query design; that is treated in `nullifier-binding-alex.md`. This document considers the
stronger interface, where the published value is a hidden query of the committed product, to test the
primitive against the surface goal at its most favorable.

The governing budget, that safe exposure requires staying below the recovery threshold set by the
number of independent parameters, is developed in `surface-vs-recovery.md`. The job here is to find
where the product's parameter count lands relative to that budget under each candidate interface.

The analysis is charitable. If pow5 gets keys, salts, constants, hidden query points, and
proof-system structure, the product is allowed the same, subject to one rule: every strengthened
variant must be feasible within Ragu, meaning constructible from commitments, openings, product and
quotient identities, split openings, and pinned witnesses inside the step budget. The derivation and
certification scheme may be replaced wholesale; nothing requires resembling the current pow5 path
(a boundary identity plus a masked quintic recurrence identity over the order-$8192$ domain, checked
by quotient-split openings). The current path is kept only as a cost reference. A variant that adds a
new heavy permutation or a hash after every evaluation is still admissible if Ragu can carry it; the
fair question is then whether that added machinery, not the product, is doing the security work.

## The public output is the design variable

A nullifier may reveal any value whose derivation is provable and which suffices for duplicate-spend
detection. So the right question is not what nullifiers usually reveal but which public-output
function is chosen and what it leaks. The candidates, from most to least faithful to Alex's stated
intuition:

1. factor-derived outputs;
2. coefficient-derived outputs;
3. evaluation-derived outputs;
4. committed-product spectrum queried through a hidden relation;
5. extracted or hashed outputs after evaluation.

Two of these are cautionary boundary cases rather than candidates. Coefficient-derived outputs are
the most dangerous, because the multiplicative identities $C_SC_T=C_{S\cap T}C_{S\cup T}$ let a few
leaked coefficients determine the rest. Direct evaluation-derived outputs are nearly as bad, because
repeated evaluations are equations in the same $m+1$ parameters. Neither should be used without a
separate exposure bound or extractor argument. The factor claim is the charitable reading: if the
factors are independently sampled and hidden, revealing all but one does not reveal the last. That
narrow intuition is reasonable, but it is a statement about factor leakage, not about a published
evaluation sequence.

## The strongest spectrum-replacement model

For a fair head-to-head against pow5, pair the product with the strongest proof-feasible
representation and query, not the simplest one.

**Representation.** Use $W$ independent product lanes, each note-bound and split-committed:

$$
T_{A,u}(X)=\prod_{i=0}^{m-1}(a_{u,i}X^{2^i}+b_{u,i}).
$$

Pin the factors before the challenge, commit the final product in $s_m=\lceil 2^m/8192\rceil$
capacity-wide splits, and certify at a challenge $z$ by recombining $T_{A,u}(z)$ and checking it
against $\prod_i(a_{u,i}z^{2^i}+b_{u,i})$. This exposes no coefficients and commits no intermediate
products. A fixed product tree of committed intermediates, each edge checked by
$P_{u,v}(z)=P_u(z)P_v(z)$, is an equally Ragu-feasible alternative if it gives better locality or
reuse; the choice is an engineering one.

**Query.** The strongest query is a hidden polynomial pullback, not the cheap multiplicative shift.
Choose a pinned per-lane map $\phi_u(Y)=\sum_{r=0}^q h_{u,r}Y^r$ and publish

$$
nf_d=\sum_{u=0}^{W-1}\rho_u^d\,T_{A,u}(\phi_u(\gamma^d))
=\sum_{u=0}^{W-1}\rho_u^d\prod_{i=0}^{m-1}(a_{u,i}\phi_u(\gamma^d)^{2^i}+b_{u,i}).
$$

Only the final mixed value is public; factors, coefficients, query maps, shifts, and weights stay
proof-bound. This certifies with the same pattern: commit the map and the pulled-back product, derive
$z$, open $\phi_u(z)$ and $U_{A,u}(z)$, and check $U_{A,u}(z)=\prod_i(a_{u,i}\phi_u(z)^{2^i}+b_{u,i})$.
The hidden affine coset $\phi_u(Y)=\delta_u+c_uY$ is the $q=1$ case; the current multiplicative query
is the still-narrower $\phi_u(Y)=c_uY$. One soundness detail: the top map coefficient $h_{u,q}$ must
be pinned nonzero if exact degree $q$ matters, since otherwise a malicious or unlucky $h_{u,q}=0$
silently degrades the map to lower degree.

**Degree budget.** The pulled-back product has degree $\le q(2^m-1)$, needing
$s_{m,q}=\lceil q2^m/8192\rceil$ splits. A four-split budget gives the frontier $q2^m\le 32768$, with
corner points $m{=}15,q{=}1$; $m{=}14,q{=}2$; $m{=}13,q{=}4$; $m{=}12,q{=}8$.

## What the strongest model is worth

The nominal prediction-relevant parameter count is $W(2m+q+2)$: $2m$ factor parameters, $q+1$ for the
map, and one weight. But the product carries per-factor scaling redundancy,

$$
\prod_{i}(a_{u,i}X^{2^i}+b_{u,i})=\Big(\prod_i a_{u,i}\Big)\prod_i\Big(X^{2^i}+\tfrac{b_{u,i}}{a_{u,i}}\Big),
$$

so only the ratios $b_{u,i}/a_{u,i}$ and one overall scale (which folds into $\rho_u$) are essential.
The effective count is closer to

$$
W(m+q+2),
$$

about $76$ for $W{=}4,m{=}13,q{=}4$ rather than $128$. The reduction is the conservative direction,
since fewer real unknowns make the system more determined for a given number of observations.

This sharpens how to spend the degree budget. The largest qualitative gain arrives at $q=1$: a hidden
affine map feeds the product non-geometric inputs $\delta_u+c_u\gamma^d$, breaking the clean
$\gamma^{2^id}$ factorization that makes the pure multiplicative query easiest to attack. A monomial
map $\phi(Y)=cY^r$ wastes the budget because it merely rescales exponents; a dense map earns it.
Raising $q$ past $1$ adds query nonlinearity with diminishing returns while trading away product
depth $m$, which is Alex's distinguishing primitive. So $m{=}15,q{=}1$ is the most spectrum-faithful
choice, and $m{=}13,q{=}4$ is the balanced point where extra split budget goes to the query rather
than to depth. Either way, against the surface budget developed in `surface-vs-recovery.md`, an
effective count near $76$ is far below the exposure a long-lived nullifier sequence demands.

## Why no bounded query rescues it

An attacker observing $(d,y_d)$ writes

$$
y_d-\sum_{u}\rho_u^d\prod_{i}(a_{u,i}\phi_u(\gamma^d)^{2^i}+b_{u,i})=0,
$$

with the affine and multiplicative queries as special cases. Once observations exceed the effective
count, the system is generically overdetermined. This is not an immediate practical break: the
equations are nonlinear, may carry symmetries and spurious solutions, and may be hard at the field
size, and the hidden-pullback version is genuinely harder than the multiplicative one. The structural
problem is that a compact, rigid closed-form model for the *entire* sequence still exists, and a
public-output function that exposes it repeatedly hands the attacker exactly that model. No
bounded-degree pullback erases the closed form; it only changes a product in $\gamma^{2^id}$ into a
product in $\phi(\gamma^d)^{2^i}$, still with $O(W(m+q))$ hidden parameters.

Any stronger leakage only worsens this. Isolated lane evaluations turn each lane into a separate
low-dimensional problem; leaked coefficients propagate through the multiplicative identities; isolating
$W-1$ lane contributions yields the last by subtraction; known or attacker-chosen maps or weights make
the system explicit.

## Where the product genuinely fits

The product is strong exactly where the interface does not repeatedly expose its closed form.

- **Ragu-native committed certification.** Witness note-bound factors and a committed final product,
  and certify by opening the product splits at a challenge against the pinned factors. This is the
  best proof-feasible way to use the product as a generator, and it sits in the same spirit as the
  pow5 quotient checks. Its honest cost: successful certification proves only that the spectrum lies
  in the small product family, so the closed-form recovery analysis still applies.
- **Keyed and salted factors.** Deriving $(a_{j,i},b_{j,i})=\mathsf{KDF}(mk,s_j,i)$ prevents global
  reuse and strengthens inter-emitter independence. It changes how parameters are sampled, not the
  effective dimension within a lane, which stays $O(N\log L)$.
- **Bounded-output use.** If a note may emit only a bounded number of observations well below the
  effective count, the product becomes a defensible bounded-use generator. This needs a consensus or
  protocol constraint enforcing the exposure bound, which is a real design change.

Three variants should stay short because they move the problem rather than solve it: iterating product
layers becomes a new AO primitive with its own cryptanalysis; hashing after each evaluation relocates
security and cost to the extractor; many independent products only grow the parameter count linearly
while multiplying commitments and openings.

## Assessment

The product is a useful proof-friendly algebraic object, not a coherent long-lived nullifier spectrum.
It is strongest as a factor-derived, certified, or bounded-output generator, and weakest exactly as a
drop-in replacement for the pow5 evaluation sequence, because that interface turns each observation
into an equation in a compact parameter set. The fairest spectrum-replacement benchmark, keyed and
salted split-committed lanes behind a hidden pullback,

$$
d\mapsto\sum_{u=0}^{W-1}\rho_u^d\prod_{i=0}^{m-1}(a_{u,i}\phi_u(\gamma^d)^{2^i}+b_{u,i}),
$$

still carries only about $W(m+q+2)$ effective parameters against a degree budget $q2^m$. Unless the
pullback degree, lane count, or an extractor layer supplies a genuinely new security argument, that
count is too small for the exposure the surface goal requires. The verdict is therefore conditional,
not dismissive: good primitive, wrong interface for a large queryable surface.
