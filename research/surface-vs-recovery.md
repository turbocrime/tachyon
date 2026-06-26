# Queryable Surface vs Recovery: The Governing Bound

## Scope

The companion documents analyze whether a given expansion primitive resists recovery once
nullifiers are public. That is the right question for a fixed nullifier interface, but it is not
the question that drives the spectrum design. The spectrum exists to maximize the **queryable
nullifier surface**: the number of distinct offsets $S$ that one note can expose, confirmable in a
single proof step over a contiguous range.

This document states the bound that actually governs that goal, separates it from per-offset
recovery hardness, and re-frames each previously analyzed variant against it. It should be read
before the product and pullback discussions, because those analyze strengthenings that do not move
the bound established here.

## Protocol objects in play

The current scheme publishes

$$
nf_d=\sum_{j=0}^{N-1}\rho_j^d\,T_j(c\gamma^d)
$$

with $N=4$ emitters, spectra $T_j$ of degree $<L=8192$, secret query shift $c$, secret geometric
weights $\rho_j$, and public coset generator $\gamma$ of order $S=16384$. A contiguous range of
offsets is confirmed in one step by the accumulator recurrence

$$
A(\gamma z)-A(z)=\sum_j w_j(z)\,T_j(z),\qquad \text{vanisher } z^S-c^S,
$$

with $A(c\gamma^d)=\sum_{k<d}\beta^k nf_k$ and $w_j(c\gamma^d)=(\rho_j\beta)^d$.

## The governing bound

Write the published sequence as an exponential sum in the offset $d$:

$$
nf_d=\sum_{j=0}^{N-1}\sum_{e=0}^{L-1}\big(t_{j,e}c^e\big)\,(\rho_j\gamma^e)^d
$$

A sequence that is a sum of $t$ geometric progressions with distinct ratios satisfies a linear
recurrence of order $t$. Berlekamp-Massey, equivalently Ben-Or-Tiwari sparse interpolation, recovers
that recurrence, and hence every frequency and amplitude, from $2t$ consecutive samples over any
field. This holds **whether or not the frequencies are secret**.

Therefore the quantity that bounds the safe surface is the mode count

$$
t=\#\{(j,e):t_{j,e}\neq 0,\ \text{frequencies } \rho_j\gamma^e \text{ distinct}\}\le N\cdot L
$$

A note is safe only while

$$
S<t
$$

with margin, since an attacker who collects $2t$ samples can predict the whole sequence. The current
sizing $S=16384<NL=32768$ is exactly this bound, not a generic count of "apparent amplitudes."

Two consequences follow immediately.

### Mode count is degree

Each emitter of degree $<L$ contributes at most $L$ frequencies $\gamma^e$. Higher emitter degree
means more modes, means larger safe surface. Degree is the surface lever.

### Only independent coefficients count

A high-degree polynomial whose coefficients are a known image of a few secrets does not raise $t$ in
any way the attacker respects. If the frequencies are structured and the amplitudes are a known
linear function of $K$ free unknowns, the attacker solves a known linear system in $K$ unknowns and
$t$ collapses to $K$. Degree only buys surface when the coefficients carry independent entropy.

This is the single fact that separates the candidate primitives.

## Why secret weights, shifts, and affine cosets do not move the bound

The surface bound is set by the count of *independent* modes, meaning modes not reducible to fewer
unknowns by a structured attack. The distinction matters for the affine-coset discussion in the
companion document, so it must be drawn carefully.

For a spectrum whose coefficients are already independent (the pow5 case), $t$ is saturated at $NL$.
Berlekamp-Massey recovers the characteristic polynomial of the sequence regardless of whether its
roots $\rho_j\gamma^e$ are public, so secret weights $\rho_j$, the secret shift $c$, and a hidden
affine coset $\phi(Y)=\delta+cY$ only reparametrize frequencies and amplitudes by maps that are
invertible given the recovered recurrence. A higher-degree fixed pullback $\phi$ of degree $q$
inflates the argument degree to $qL$, but the $qL+1$ resulting coefficients are a fixed linear image
of the original $L$, so the independent count is unchanged and $t$ does not grow. Against the surface
goal these are all neutral.

This is consistent with, not contrary to, the companion claim that the affine map "breaks the clean
$\gamma^{2^id}$ factorization." That claim is about a *compact-family* primitive such as Alex's
product, where the multiplicative query yields a sequence with few independent modes and a small
structured recovery system. There an affine input genuinely raises the *nominal* mode count and
complicates the easiest factorization attack. But the effective independent dimension stays near
$W(m+q+2)$, because the underlying generator still has only that many free parameters. So the
pullback is a recovery-hardness knob: useful for a compact-family primitive on a *fixed* interface,
and irrelevant to an already-independent spectrum. In neither case is it a surface knob.

## Surface cost is separable from sweep cost

The accumulator recurrence is order one in the coset variable, and the advance term reads each
spectrum out of its commitment at the challenge point. The degree of $T_j$ never enters the
recurrence order of the sweep. The price of degree is paid once, in the spectrum's own quotient
certification (more capacity-wide splits), not per offset.

This separation is what makes "maximize degree" a real strategy rather than a proving-cost
explosion. Surface scales with committed degree; the per-range sweep stays flat.

## The degree-maximizing construction

Because the sweep is degree-agnostic, the surface-optimal layout is **few emitters of very high
degree** rather than many emitters at the rank cap. Concretely, collapse the $N$ degree-$L$ traces
into one degree-$D$ pow5 trace with $D=NL$, every coefficient independent because the recurrence ran
$D$ rounds. Query on a coset of order $S<D$, certify the long trace with the same masked quintic
recurrence identity over the order-$D$ domain at $D/L$ quotient splits, and sweep with the existing
order-one accumulator.

Against the current four-emitter layout this gives the same amplitude budget $t=D=NL$, the same
split count, but one boundary identity and one recurrence identity instead of $N$ of each, and a
single committed object the lift path can sweep. Surface scales with committed degree at order-one
sweep cost.

## Delegation makes the budget concrete, and unifies it with unlinkability

Delegation sets the adversary model. A sync service is handed an arbitrary sequence of nullifier
*values* $nf_d$ for a window of offsets, confirms their exclusion from the chain, and proves it; the
wallet later folds that proof into its spendable proof. The sync service therefore observes
$(d, nf_d)$ pairs directly. This is the recovery model exactly, not the weaker on-chain-presence
model, and possibly colluding services span many windows of one note.

The required property is that delegation windows which do not overlap cannot be correlated. That is
the recovery bound restated as a distinguishing attack:

- every window of a note is a segment of the *same* exponential sum, with note-fixed frequencies
  $\rho_j\gamma^e$ and amplitudes $t_{j,e}c^e$;
- deciding whether two windows share a note asks whether a single $t$-mode model fits their union;
- a single model always fits while the combined sample count stays below the unique-fit threshold
  $\approx 2t$, and fits only for same-note windows above it.

So the **total lifetime exposure across all delegation windows** must stay below threshold, which is
exactly the surface invariant $S<t$. Surface budget and delegation-exposure budget are the same
budget. The salt-and-shift machinery is what guarantees no sub-threshold shortcut exists: by making
the frequencies ($\rho_j$, $c$) and amplitudes (per-emitter salts) note-secret and unstructured, it
forces the adversary into the full structured-system attack that needs the whole $\approx 2t$ sample
budget the invariant denies. A public or structured frequency ladder could otherwise admit a cheaper
distinguisher well below threshold. Any alternative scheme must keep this machinery or an equivalent.

This qualifies the degree-maximizing construction. Collapsing $N$ emitters into one degree-$D$ trace
preserves the threshold ($t=D$ either way) and the secret shift $c$, but it discards the $N$
independent secret weight-ladders $\rho_j$ and per-emitter salts. Those do not raise $t$; they widen
the *margin* against sub-threshold statistical and structural distinguishers, since a sum of ladders
is more mixed than a single ladder $\rho^d T(c\gamma^d)$. The genuine trade is therefore fewer
identities (proving cost) against more mixing (unlinkability robustness). A defensible middle is to
keep several secret weight-ladders and salts while still raising per-emitter degree above $L$, rather
than collapsing all the way to one emitter.

## The hard ceiling

No range-confirmable scheme beats

$$
S<t=\#\{\text{independent committed coefficients}\}
$$

The reason is structural. A one-step range sweep requires $d\mapsto nf_d$ to be a low-order linear
recurrence to certify, but the mode count *is* the recurrence order. The design escapes the apparent
contradiction by paying the high recurrence order once, inside the committed spectrum (degree $L$,
certified once), while keeping the sweep order one. Any attempt to win superlinear surface from
degree requires $nf_d$ to be a nonlinear, non-exponential-sum function of $d$, which is exactly what
breaks the linear accumulator. A per-offset extractor (hash after evaluation) is the same dead end:
it defeats recovery but destroys the polynomial prefix-sum, so the range can no longer be confirmed
in one step.

## Verdict on each variant against the surface goal

- **Hidden affine coset / higher fixed pullback:** surface-neutral. It is a recovery-hardness knob
  for a fixed interface, valuable for a compact-family primitive (where it raises nominal modes and
  breaks the easy factorization) but irrelevant to an already-independent spectrum, whose $t$ is
  saturated. Against an independent pow5 spectrum it is not worth the added $\delta$ binding and the
  $-\delta$ shift in every recurrence identity.
- **Alex's binary product as a spectrum:** anti-aligned. It maximizes degree ($2^m-1$) while filling
  $2^m$ coefficients from $m+1$ secrets, so $t$ collapses to roughly $m$ and the safe surface
  collapses with it. It pays for almost no entropy.
- **Per-offset extractor (App A, hash after evaluation):** strong against recovery, but destroys the
  linear accumulator and therefore single-step range confirmation. Suited to small fixed-output
  nullifier designs, not to the surface goal.
- **Degree-maximized pow5 trace:** the correct lever for surface. Independent coefficients make
  degree real surface, and the degree-agnostic sweep keeps the per-range cost flat. The qualification
  is unlinkability: the secret shift and the secret weight-ladders must survive, so the right form is
  raising per-emitter degree above $L$ while keeping several emitters and their salts, not collapsing
  to a single ladder. Surface is then bounded by the split budget and the $S<t$ margin.

## Bottom line

For the surface goal the relevant security parameter is the count of independent committed
coefficients, recovered against by Berlekamp-Massey rather than by any frequency-hiding trick. The
same count, through the $S<t$ invariant, is what keeps non-overlapping delegation windows
uncorrelatable, since a sync service observes nullifier values directly and the safe lifetime
exposure is exactly this budget. The spectrum should therefore maximize independent coefficients via
long pow5 traces, raise per-emitter degree above $L$ while retaining several secret weight-ladders
and salts for unlinkability margin, and rely on the order-one accumulator to keep range confirmation
cheap. The product and pullback analyses in the companion documents remain correct about
per-interface recovery, but they address a different question and do not bear on how large the
queryable surface can be made or on whether windows correlate.
