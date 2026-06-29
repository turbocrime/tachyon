# Binding the Direct-Derivation Product: $nf_e=f(e)$

## What this analyzes

Alex's clarified proposal is a direct nullifier derivation function. For a note, sample
factors $(a_i,b_i)$ and set

$$
nf_e=f(e)=\prod_{i=0}^{m-1}\big(a_ie^{2^i}+b_i\big),
$$

one nullifier per epoch $e$, with $f$ the binary product of
`nullifier-expansion-alex-vs-pow5.md`, degree $2^m-1$, and $m=13$ filling the
length-$8192$ budget. The factors are picked per note, or derived from a seed.

This is not the construction steelmanned in `nullifier-risk-alex.md`, which pairs the
product with split-committed lanes behind a hidden polynomial pullback and asks what a
published *query* sequence leaks. That document answers the recovery question for the
strongest interface. Alex's actual proposal is the plain evaluation map $nf_e=f(e)$, and
for it the first question is not what the sequence leaks but what fixes the factors in the
first place. That question is binding, and here binding is a soundness requirement, not
privacy hygiene.

## Binding is mandatory

A nullifier's one job is uniqueness: a given note must yield exactly one nullifier per
epoch, so a second spend reveals a colliding value and is rejected. The derivation
$nf_e=f(e)$ delivers this only if $f$ is fixed by the note. If the spender may choose the
factors at spend time, they evaluate a fresh $f$, publish an $nf_e$ that collides with
nothing on chain, and spend the note again. Uniqueness, and with it duplicate-spend
detection, is gone.

In the proof this is the free-witness trap. The spend circuit's natural check is

$$
nf_e\stackrel{?}{=}\prod_{i=0}^{m-1}\big(a_ie^{2^i}+b_i\big),
$$

and it binds $nf_e$ only if every factor on the right is independently pinned. With the
factors as free witnesses the equation is vacuous: for any target $nf_e$ the prover solves
for factors that satisfy it. The check looks like a derivation but constrains nothing.
Pinning the factors is therefore not an optimization; it is the entire content of the
nullifier's soundness, and the product structure does nothing to supply it.

The freedom is wider than one tuple. Rescaling factor $i$ by $\lambda_i$ multiplies the
whole polynomial, and hence every $nf_e$, by $\lambda_i$; the polynomial depends on the
factors only through the base $B=\prod_ib_i$ and the ratios $r_i=a_i/b_i$, the $m+1$
essential parameters of `nullifier-expansion-alex-vs-pow5.md`. So even a partial pinning
that leaves the per-factor scale free leaves $f$ underdetermined. What must be pinned is
$f$ itself, equivalently the canonical $(B,r_0,\ldots,r_{m-1})$.

Pinning must also reach the nullifier key. The factors, or the seed they derive from, must
be $nk$-bound, or the published nullifier is not tied to spend authority and a party
without the spend key could derive it. The present scheme already carries this chain:
$pk=\mathsf{Poseidon}(\texttt{PK\_DOMAIN},ak_x,nk)$ pins $nk$ into the note commitment, and
the nullifier salt is $\psi'=\mathsf{Poseidon}(\psi,nk)$. Any binding for the product must
thread the same $nk$ dependence, not merely fix some factors.

The contrast with pow5 is the point. The pow5 emitter derives its spectrum from the master
key by a keyed nonlinear schedule, and that schedule does three jobs at once: it binds the
spectrum to $mk$, and through $mk$ to $cm$; it supplies the recovery hardness; and it
performs the expansion, all inside one quotient-certified object. Alex's product is
expansion only. It produces a polynomial but says nothing about where its coefficients come
from, so binding is re-opened as a separate obligation.

## The space of binding approaches

Each approach below is read on four axes: in-circuit cost, what is actually bound, whether
the *product structure* contributes anything to the binding, and whether recovery hardness
arrives with it.

**A. Commit the raw factors.** Put the factors, or the canonical $(B,r_i)$, into the note
commitment. The spend circuit opens $cm$, recomputes $f(e)$ (the powers $e^{2^i}$ by $m-1$
repeated squarings, then $m$ multiply-adds and $m-1$ products, a few dozen multiplications,
negligible against the step budget), and asserts equality to $nf_e$. The factors are now
pinned, the free-witness trap is closed, and the evaluation is cheap.

What it costs is note size: $m+1$ to $2m$ extra committed field elements. What it does not
do is use the product for anything. Once the canonical coefficients are committed, the
object is a committed degree-$8192$ polynomial with $m+1$ degrees of freedom, and the
in-circuit check is just "evaluate the committed polynomial at $e$." Any $(m+1)$-parameter
secret binds identically; the factored form contributes nothing, and the transparent-family
recovery weakness of the companion documents is carried along unchanged. Binding by
commitment works and makes the factorization irrelevant.

**B. Commit a seed; derive the factors.** Commit only a seed, say $\psi'$, and set
$(a_i,b_i)=\mathsf{PRF}(\psi',i)$, re-deriving the factors in-circuit before evaluating the
product. The note stays small and the factors inherit the seed's binding, including its
$nk$ dependence.

The cost is the PRF. A Poseidon-based PRF emitting on the order of $2m$ factor elements is
several step-budgets of hashing for $m=13$, more than one step can hold, so the derivation
is inherently a multi-step expansion. That is structurally the same object the pow5 emitter
already is: a keyed expansion split across steps. Approach B does not add a layer pow5
lacks; it reconstructs pow5's layer around a weaker core. And it is the same layer the
recovery analysis asked for. `nullifier-expansion-alex-vs-pow5.md` observes that the product
is the Naor-Reingold subset product without the one-way map; a PRF over the seed is exactly
that one-way map. Once present it both binds the factors and supplies recovery hardness, and
the product's factored form is subordinate to the PRF doing the security work. Binding by
derivation and recovery hardness are one layer.

**C. Commit the polynomial, open per epoch.** The most Ragu-native option commits $f$ once.
The wallet builds the polynomial prover-side at note creation and binds its commitment into
$cm$; a commitment is a header-sized value, where the polynomial itself can never sit. Each
nullifier is then an opening of that committed polynomial against the published $nf_e$ by
the standard challenge-opening argument, so the per-nullifier cost is an opening rather than
a re-derivation of the factors.

This binds $f$ cleanly, and again without the factorization. The commitment pins whatever
polynomial was committed, up to trailing zeros, and is blind to whether that polynomial
factors as a binary product. One would need to additionally certify family membership only
if security rested on it, and binding does not. If membership ever did matter, commit
equality alone would not pin the exact degree, since a lower-degree polynomial with a zero
top coefficient passes the same commitment, so the top coefficient would have to be guarded
nonzero; binding sidesteps this by not depending on the family. As a binding mechanism C is
the cleanest of the lot and the clearest demonstration that the product is incidental: it
commits a polynomial and opens it, and the polynomial's internal form never enters.

**D. Hash the output.** Publish $nf_e=H(e,f(e))$ instead of $f(e)$, binding by proving the
hash from pinned factors. `surface-vs-recovery.md` rejects a per-offset extractor because it
destroys the linear accumulator that lets a contiguous range be confirmed in one step, but
that objection is specific to range confirmation. Alex's direct derivation confirms one
epoch at a time and has no accumulator to destroy, so the extractor is admissible here, and
it removes the recovery problem outright by hiding $f$ behind a one-way map.

But it removes the product with it. Once the output is $H(e,f(e))$, $f$ need only be some
keyed function of the note; the binary product is one arbitrary choice with no advantage
over hashing a simpler keyed value, and the construction reduces to the standard keyed
nullifier $nf_e=H(e,\text{key})$. The extractor is the security-relevant part and the
product is along for the ride.

**E. Commit the sequence.** At the far end, precompute the nullifier sequence
$nf_0,nf_1,\ldots$ over the note's lifetime at creation, bind a Merkle or vector root into
$cm$, and spend by revealing $nf_e$ with a membership opening. No algebra runs in the spend
circuit; binding is a single membership check.

The price is paid at creation and in generality. The committer must know the factors at
note-creation time and precompute up to the full lifetime of nullifiers, of order $16384$,
and the structure is again irrelevant since any sequence commits the same way. Without
padding, the committed length leaks the intended lifetime. E is worth naming as the extreme
where binding uses no in-circuit algebra, and it makes the same point from the opposite
direction: the product never appears.

A reuse shortcut is not a sixth option. Deriving the factors from existing committed note
fields through a field-arithmetic map is approach A with relabeled inputs if the map is
transparent, sharing its irrelevance of structure, and approach B if the map is one-way.
There is no transparent way to bind the factors that also makes them hard to recover.

## The one layer

Every approach lands in one of two places, and the split is the whole story. Either the
binding commits a polynomial, factors, or sequence directly, as in A, C, and E, in which
case the committed object could be anything and the product's factored form contributes
nothing; or the binding imports a one-way derivation or extraction layer, as in B and D, in
which case that layer is simultaneously the binding mechanism and the recovery-hardness
mechanism, and the product is subordinate to it.

So binding never requires the factored form. The reason is structural. Pow5 is the fixed
point where expansion and derivation are the same object, so a single keyed, certified
spectrum pays for binding, mixing, and expansion together. Alex's product separates
expansion from derivation. It is a good expansion, but a direct nullifier needs the
derivation too, and re-importing the derivation lands exactly on the one-way layer the
recovery analysis already said the product was missing. The binding obligation and the
recovery obligation are the same missing layer seen from two sides.

## Assessment

The verdict matches the companion documents and does not soften. The binary product is a
proof-friendly factorized polynomial family. As a direct nullifier derivation $nf_e=f(e)$ it
inherits a mandatory binding obligation its own structure cannot discharge: either binding
commits the polynomial outright and the factorization is redundant (A, C, E), or binding
rides on a PRF or extractor that is itself the security-relevant component (B, D). In no
configuration does the factored form do the binding work, and in the two configurations that
also fix the recovery weakness, the added one-way layer is what fixes it.

This is not a reason the idea is bad; it is a precise statement of what the idea is. The
product belongs wherever a committed polynomial of compact algebraic shape is useful and its
closed form is not repeatedly exposed, which is the conclusion `nullifier-risk-alex.md` and
`nullifier-expansion-alex-vs-pow5.md` reach from the interface and primitive sides. For a
directly published, long-lived nullifier sequence it carries a binding cost equal to the
layer it was hoped to avoid. The governing budget for how much such a sequence may expose,
once bound, is in `surface-vs-recovery.md`.
