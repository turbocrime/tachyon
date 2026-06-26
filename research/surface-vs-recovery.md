# Queryable Surface vs Recovery: The Governing Bound

## What this analyzes

The companion documents ask whether a given expansion resists recovery once nullifiers are public.
That is the right question for a fixed interface, but it is not what drives the spectrum design. The
spectrum exists to maximize the **queryable nullifier surface**: the number of distinct offsets $S$
one note can expose, confirmable in a single proof step over a contiguous range.

This document establishes the bound that governs surface, shows it is the same bound that governs
recovery and delegation unlinkability, separates it from the sweep cost, and reads off the one lever
that actually grows surface in the present implementation. It is the lens through which the other
documents should be read.

## Protocol objects in play

The current scheme publishes

$$
nf_d=\sum_{j=0}^{N-1}\rho_j^d\,T_j(c\gamma^d),
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
nf_d=\sum_{j=0}^{N-1}\sum_{e=0}^{L-1}\big(t_{j,e}c^e\big)\,(\rho_j\gamma^e)^d.
$$

A sum of $t$ geometric progressions with distinct ratios satisfies a linear recurrence of order $t$,
and Berlekamp-Massey, equivalently Ben-Or-Tiwari sparse interpolation, recovers that recurrence, and
hence every frequency and amplitude, from $2t$ consecutive samples over any field. This holds whether
or not the frequencies are secret. The quantity that bounds safe exposure is therefore the mode count

$$
t=\#\{(j,e):t_{j,e}\neq 0,\ \rho_j\gamma^e \text{ distinct}\}\le N\cdot L,
$$

and a note is safe only while $S<t$ with margin. The current sizing $S=16384<NL=32768$ is exactly
this bound, not a generic count of apparent amplitudes.

Two consequences follow.

**Mode count is degree.** Each emitter of degree $<L$ contributes at most $L$ frequencies $\gamma^e$,
so higher degree means more modes means larger safe surface. Degree is the surface lever in
principle.

**Only independent coefficients count.** A high-degree polynomial whose coefficients are a known image
of a few secrets does not raise $t$ in any way the attacker respects: if the frequencies are
structured and the amplitudes are a known linear function of $K$ unknowns, the attacker solves a
linear system in $K$ and $t$ collapses to $K$. Degree buys surface only when the coefficients carry
independent entropy. This is the single fact that separates the candidate primitives.

## Frequency-hiding is surface-neutral

Secret weights $\rho_j$, the secret shift $c$, and a hidden affine coset $\phi(Y)=\delta+cY$ do not
change $t$. Berlekamp-Massey recovers the characteristic polynomial regardless of whether its roots
are secret, so these only reparametrize frequencies and amplitudes by maps invertible given the
recovered recurrence. A fixed pullback of degree $q$ inflates the argument degree to $qL$, but the
$qL+1$ resulting coefficients are a fixed linear image of the original $L$, leaving the independent
count, and hence $t$, unchanged. For surface, all of these are neutral.

They are not pointless, and the companion claim that the affine map "breaks the clean
$\gamma^{2^id}$ factorization" is correct in its own scope: against a compact-family primitive like
Alex's product, whose sequence has few independent modes, an affine input raises the nominal mode
count and complicates the easiest factorization attack. That is a recovery-hardness gain on a fixed
interface, against a primitive whose effective dimension stays small either way. It is a different
axis from surface, and on an already-independent spectrum it adds nothing. Frequency-hiding earns its
place in the design for a different reason, given under delegation below.

## Surface cost is separable from sweep cost

The accumulator recurrence is order one in the coset variable, and its advance term reads each
spectrum out of its commitment at the challenge point. The degree of $T_j$ never enters the recurrence
order of the sweep. The price of degree is paid once, in the spectrum's own quotient certification,
not per offset. Surface scales with committed degree while the per-range sweep stays flat.

## Delegation unifies surface with unlinkability

Delegation sets the adversary model and shows why this one bound governs everything. A sync service is
handed an arbitrary sequence of nullifier *values* $nf_d$ for a window of offsets, confirms their
exclusion from the chain, and proves it; the wallet later folds that proof into its spendable proof.
The service observes $(d,nf_d)$ pairs directly, which is the recovery model exactly, and colluding
services span many windows of one note.

The required property is that non-overlapping windows cannot be correlated, which is the recovery
bound restated as a distinguishing attack. Every window is a segment of the same exponential sum with
note-fixed frequencies $\rho_j\gamma^e$ and amplitudes $t_{j,e}c^e$. Deciding whether two windows
share a note asks whether a single $t$-mode model fits their union, and such a model always exists
while the combined sample count stays below the unique-fit threshold $\approx 2t$, and exists only for
same-note windows above it. So the total lifetime exposure across all windows must stay below
threshold, which is the same invariant $S<t$. Surface budget and delegation-exposure budget are one
budget.

This is what frequency-hiding is for. By making the frequencies ($\rho_j$, $c$) and amplitudes (the
per-emitter salts) note-secret and unstructured, the salt-and-shift machinery removes any
sub-threshold shortcut, forcing the adversary into the full structured attack that needs the whole
$\approx 2t$ samples the invariant denies. A public or structured frequency ladder could otherwise
admit a cheaper distinguisher well below threshold. Any alternative scheme must keep this machinery or
an equivalent.

## The lever in the present implementation

Degree is the surface lever in principle, but the commitment cannot hold a polynomial longer than the
present spectrum: each emitter is capped at $L=8192$ coefficients. Per-emitter degree-maximization is
therefore off the table. The only available lever is the emitter count $N$.

Adding an emitter adds one more degree-$L$ spectrum with its own salt and weight, so $t=NL$ grows
linearly, at a linear proving cost: one more boundary identity, recurrence identity, commitment, and
opening per emitter. The accumulator sweep stays order one regardless of $N$. This lever is doubly
aligned, because more independent weight-ladders also widen the unlinkability margin against
sub-threshold distinguishers, a sum of ladders being harder to separate than a single one.

## The hard ceiling

No range-confirmable scheme beats

$$
S<t=\#\{\text{independent committed coefficients}\}.
$$

The reason is structural. A one-step range sweep requires $d\mapsto nf_d$ to satisfy a low-order
linear recurrence to certify, yet the mode count is itself the recurrence order. The design escapes
the apparent contradiction by paying the high order once, inside the committed spectrum, while keeping
the sweep order one. Winning superlinear surface from degree would require $nf_d$ to be a nonlinear,
non-exponential-sum function of $d$, which is exactly what breaks the linear accumulator. A per-offset
extractor (hashing after evaluation) is the same dead end: it defeats recovery but destroys the
polynomial prefix-sum, so the range can no longer be confirmed in one step.

## Verdict on each variant against the surface goal

- **Hidden affine coset / higher fixed pullback:** surface-neutral. A recovery-hardness knob for a
  compact-family primitive on a fixed interface, irrelevant to an already-independent spectrum, and
  not worth the added $\delta$ binding and the $-\delta$ shift in every recurrence identity.
- **Alex's binary product as a spectrum:** anti-aligned. It maximizes degree while filling $2^m$
  coefficients from $m+1$ secrets, so $t$ collapses to roughly $m$ and the surface collapses with it.
- **Per-offset extractor:** strong against recovery, but it destroys the linear accumulator and so
  single-step range confirmation. Suited to small fixed-output nullifiers, not to surface.
- **More pow5 emitters:** the correct lever in the present implementation. Each emitter is independent
  degree-$L$ entropy, $t=NL$ grows linearly, the sweep stays flat, and unlinkability margin improves.

## Bottom line

The security parameter for surface is the count of independent committed coefficients, recovered
against by Berlekamp-Massey rather than by any frequency-hiding trick, and the same count through
$S<t$ is what keeps non-overlapping delegation windows uncorrelatable. Two practical consequences
follow. First, grow surface by adding pow5 emitters, not by enlarging or restructuring the spectrum
polynomial, which the commitment cannot hold and which the alternatives cannot improve. Second, since
nothing enforces the $S<t$ margin today, bound the offset in-circuit below threshold (for example
$d<t/2$) so a note that exhausts its budget is cleanly retired rather than wrapping into correlatable
reuse. The product and pullback analyses in the companion documents remain correct about per-interface
recovery; they simply address a different question and do not bear on how large the surface can be
made or on whether windows correlate.
