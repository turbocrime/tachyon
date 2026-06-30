# Widening the Spectrum: Credible Expansion and Orbit Width

## What this analyzes

The companion documents establish the bound and prosecute the current
instantiation. `surface-vs-recovery.md` shows the security parameter is
$S<t$, with $t$ the count of *independent* committed coefficients, and warns
that a high-degree polynomial whose coefficients are a known image of a few
secrets "does not raise $t$ in any way the attacker respects."
`trace-as-spectrum-attack.md` then shows that the pow5 emitters are exactly such
a polynomial: the published spectra are deterministic images of one small,
shared key schedule, so the headline $NL=32768$ is an accounting fiction and the
real $t$ is roughly the schedule size, $\sim 137$.

This document is the design response. It does not dispute either critique; it
takes them as the specification. The question it answers is narrow and concrete:
*given that $t$ is the independent key-schedule dimension, how do we make that
dimension large and genuinely independent, without exceeding the proof budget?*
The answer separates two levers that were previously conflated, and it is honest
about the one critique it does not touch.

## The governing quantity, restated

All four emitters share one expanded key schedule, differing only by salt, so
the schedule **is** the secret that regenerates every spectrum. Write the
schedule width (distinct round keys before the emitter's period repeats) as $W$.
Then, to the precision the attacker respects,

$$
t \;\approx\; W + (\text{salts}) + (\text{shift, weights}),
$$

and the surface is dominated by $W$. The current scheme uses a small shared
schedule ($W \approx 128$ in the analysis, $256$ in the present code), cycled
many times across the $L=8192$ emitter rounds. Raising $t$ means raising $W$ --
but only if the extra keys are *independent*, not a cheap image of the compact
master key $\mathsf{mk}$.

## Two levers, previously conflated

The expansion is a keyed $R_x$-round pow5 cipher that stretches $\mathsf{mk}$
into the schedule. Two distinct properties of it govern $t$, and they are
independent:

- **Depth $R_x$ = credibility.** A schedule key counts toward $t$ only while the
  expansion is one-way enough that an attacker cannot compress the $W$ keys back
  to the small $\mathsf{mk}$. The expansion's symbolic degree is $5^{R_x}$, so
  depth is what buys uncompressibility.
- **Width $W$ = part count $P$.** The schedule is assembled from $P$ committed
  parts, each holding $\mathrm{EK\_PART\_SIZE} = L/R_x$ keys, so
  $W = P\cdot L/R_x$. The choice $P=2$ was a default of the prior
  implementation, not a constraint.

The effective surface is the smaller of the two:

$$
t \;\approx\; \min\big(\,\underbrace{P\cdot L/R_x}_{\text{width}},\;\underbrace{\mathrm{capacity}(R_x)}_{\text{one-wayness}}\,\big).
$$

Conflating them is what made "more rounds" and "more keys" look like the same
knob. They are not. Driving $R_x$ down widens the schedule ($L/R_x$ grows) but
*lowers* one-wayness, so past a point the wide schedule is a mirage that
collapses to $\mathsf{mk}$ -- below even the current scheme. The floor on $R_x$
is one-wayness, not the proof budget.

## Credible expansion: $R_x = 32$

We hold the expansion at $R_x=32$, degree $5^{32}\approx 2^{74}$. This is well
short of the $\sim 110$-round saturation noted in `trace-as-spectrum-attack.md`,
which is the correct place to be: saturation is needed for the *emitter*, whose
$8192$ rounds saturate the published composition regardless, but the expansion's
job is narrower -- resist compressing its $W$ outputs back to $\mathsf{mk}$. At
$2^{74}$ that compression is a high-degree structured solve in the master key;
at the shallow alternatives ($R_x=8$ is $2^{19}$, $R_x=4$ is $2^9$) it is not, so
those widen $W$ on paper while the real independent count stays at
$|\mathsf{mk}|$. Thirty-two rounds is the conservative side of the crossover: a
real cipher with a full round-key schedule, not a shallow cycling stub.

This does not make the expansion one-way in the saturated sense, and we do not
claim it does. It makes the *width credible* -- the $W$ committed keys are a
genuinely high-degree image of $\mathsf{mk}$, so the attacker cannot quietly
replace $W$ unknowns with $|\mathsf{mk}|$.

## Width without sacrificing depth: $P = 4$

Because width and depth are separate, we recover width by adding parts rather
than by lowering $R_x$. At $R_x=32$, $\mathrm{EK\_PART\_SIZE}=L/R_x=256$, so
$P=4$ gives

$$
W \;=\; P\cdot L/R_x \;=\; 4\cdot 256 \;=\; 1024 .
$$

A $1024$-key schedule -- the width an $R_x=16$ expansion would give -- but here
every key is backed by the credible $32$-round expansion. So $t$ rises from the
apparent $\sim 137$ of the small shared schedule toward $\sim 1024$ *real*. The
cost is paid in expansion steps ($P$ of them) and in a single assembly step, not
in the per-emitter query path (see budget below).

## One longer orbit, not a split and not shared-small

With two independent master-key parts one could instead give the emitters
*separate* schedules. We do not, because for a fixed key budget it buys nothing
the bound respects. Under any partition the independent space is the same
$\mathrm{span}$ of committed keys, so $t$ is identical; what differs is
second-order:

- A single longer orbit of width $W$ cycles the $L$-round emitter $L/W$ times --
  at $W=1024$, eight times -- the *least* self-similar arrangement. Two
  independent half-width orbits cycle each schedule twice as often, and the
  shared small schedule of today cycles it thirty-two times. Since the periodic
  key schedule is precisely the structure the cryptanalysis flags as a
  liability, less periodicity is strictly better.
- Splitting also exposes each base part in more published emitters and multiplies
  the witnessed part-polynomials in the derivation step, for no gain in $t$.

So the design is one orbit, made wide and credible, rather than several narrow
ones. Surface is the total independent key count under one-wayness; the
partition is a periodicity-and-cost question, and the single orbit wins it.

## The off-domain shift is load-bearing

A point easy to lose: each spectrum is the interpolant of the $8192$ emitter
round-states over the order-$L$ domain $\langle\omega\rangle$, so
$T_j(\omega^r)=s_{j,r}$ -- **evaluation at a domain point is a round-state.** The
query reads $T_j$ at $c\gamma^d$, where $\gamma$ has order $S=2L$ (so
$\omega=\gamma^2$) and $c$ is the secret shift. If $c\in\langle\gamma\rangle$,
then $c\gamma^d$ lands in $\langle\omega\rangle$ for half the offsets and those
nullifiers expose raw round-states $\sum_j\rho_j^d s_{j,r}$ directly. Because
$c\notin\langle\gamma\rangle$ the query coset is disjoint from
$\langle\omega\rangle$, and every $nf_d$ is instead a Lagrange combination of the
whole trace,
$\sum_r s_{j,r}\,\ell_r(c\gamma^d)$.

`surface-vs-recovery.md` is right that the secret shift is surface-neutral for
Berlekamp-Massey. But it is not neutral here: it is the single invariant
standing between "Lagrange combinations of the trace" and "raw round-states."
The design therefore pins $c\notin\langle\gamma\rangle$ as a secret, note-bound,
circuit-enforced invariant. This is not a new defense; it is making explicit a
property the construction was silently relying on.

## What improves, against the current scheme

| | current | this design |
|---|---|---|
| schedule width $W$ (effective $t$) | $\sim 128\text{--}256$, apparent | $\sim 1024$, credible |
| expansion depth | $64$ rounds | $32$ rounds (credible, not saturated) |
| emitter periodicity | $\times 32$ | $\times 8$ |
| master-key round keys | $6$ | $32$ |
| derivation step | reconstructs from parts, per emitter | single-input, $P$-independent |

The surface roughly quadruples and, more importantly, becomes the *kind* of
surface the bound respects -- credible high-degree key material rather than a
small schedule dressed up as $NL$.

## What this does not fix

Intellectual honesty requires the other column, and it is the same one the
companion documents name.

- **The trace-as-spectrum interface is unchanged.** We still publish linear
  functionals of the full state trace, $nf_d=\sum_j\rho_j^d T_j(c\gamma^d)$. That
  is the deepest critique in `trace-as-spectrum-attack.md`, and widening the
  orbit does not address it: a richer, doubled orbit raises the work to invert
  the window, but it is the same window. Only changing the interface (a
  per-offset extractor, at the cost of single-step range confirmation) would.
- **$S<t$ is still not satisfied.** With $t\approx 1024$ and $S=16384$, the
  system remains overdetermined; security continues to rest on the computational
  hardness of the structured solve, not on the surface bound. The redesign
  narrows the gap (from $\sim 120\times$ to $\sim 16\times$) but does not close
  it.
- **The research's own levers are not taken here.** `surface-vs-recovery.md`
  prescribes adding emitters (raising $t=NL$ linearly) and bounding the offset
  in-circuit at $d<t/2$ so a note retires before wrapping into correlatable
  reuse. This pass does neither; both compound cleanly with a wide credible
  orbit and are the natural next steps.

## Bottom line

Separating expansion *depth* from schedule *width* turns a single muddled knob
into two. Depth ($R_x=32$) makes width credible; width ($P=4$) makes the surface
large; one longer orbit minimizes periodicity; and the off-domain shift, now
pinned, keeps the query from reading the trace directly. The effective surface
goes from an apparent $\sim 137$ to a credible $\sim 1024$ at a flat per-query
cost. None of this rescues the trace-as-spectrum interface or satisfies $S<t$ --
those remain open, and remain the right place to spend the next effort.
