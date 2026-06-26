# The Case Against the Trace as Spectrum

## What this analyzes

The companion documents are charitable. `nullifier-risk-current.md` grants the pow5 emitter "a
plausible cryptographic-expansion story" and files the trace-as-spectrum interface under "warrants
dedicated cryptanalysis." This document withdraws the charity and prosecutes the choice directly.
The thesis is simple and uncomfortable: almost none of the work the scheme appears to do is real.
The $8192$ rounds are mostly theater, the $S<NL$ margin is an accounting fiction, the security rests
on a secret far smaller than advertised, and the one interface decision that defines the whole design
(publishing weighted samples of the *trace interpolant*) is the single decision with no supporting
literature and several structural features pointing the wrong way.

Each section below is a load-bearing assumption stated as the scheme's defenders would state it,
followed by what is actually true. None of these is a claimed break. The point is worse than a break:
it is that the foundation is not where the design thinks it is.

## "The security parameter is $NL=32768$, comfortably above $S=16384$."

This is the headline number, and it is not a security parameter. It counts apparent amplitudes
$t_{j,e}$ in the exponential-sum form

$$
nf_d=\sum_{j}\sum_{e}\big(t_{j,e}c^e\big)(\rho_j\gamma^e)^d,
$$

as if the $NL$ coefficients $t_{j,e}$ were free. They are not free, and the scheme's own documents
say so in the next breath. The spectra are deterministic images of a six-element master key under
Poseidon and pow5. The honest count is the dimension of the secret that regenerates the entire
sequence:

$$
\underbrace{128}_{\text{key schedule}}+\underbrace{4}_{\text{salts}}+\underbrace{1}_{\text{shift }c}+\underbrace{4}_{\text{weights }\rho_j}\approx 137.
$$

Everything an attacker wants is a function of those $\sim 137$ field elements. The interpolated
coefficients $t_{j,e}$ are not $32768$ independent unknowns; they are $32768$ *evaluations of a map*
from a $137$-dimensional domain. The governing bound established in `surface-vs-recovery.md` is
$S<t$ where $t$ is the count of *independent* committed coefficients, and it explicitly warns that a
high-degree polynomial whose coefficients are a known image of a few secrets "does not raise $t$ in
any way the attacker respects." The pow5 trace is exactly such a polynomial. The $S<NL$ comparison
measures the wrong quantity by more than two orders of magnitude.

This does not by itself mean the sequence is recoverable from $16384$ samples. It means the comfort
of the $32768$ figure is unearned, and the real question was never the amplitude count. The real
question is the hardness of solving a structured system in $\sim 137$ unknowns given the recurrence,
and that question has never been asked.

## "Eight thousand rounds of nonlinear mixing protect the spectrum."

Two facts hollow this out.

**The degree saturates after round $\sim 110$.** The defense rests on the symbolic degree of the
state in the secret growing as $5^r$. Over the Pallas base field $p\approx 2^{254}$ this growth is
real only until the exponent wraps modulo $p-1$:

$$
\log_5 p \;=\; \frac{254}{\log_2 5}\;\approx\;109.5.
$$

Past round $\sim 110$ the algebraic degree in the secret is saturated. The remaining $\sim 8080$
rounds add no new algebraic complexity in the only variable that matters to a solver. They iterate a
map whose degree is already maxed. The trace gets *longer*, not *deeper*. A defender who points at
"$5^r$ growth" is describing the first $1.3\%$ of the computation and silently extrapolating the
other $98.7\%$.

**The recurrence is bidirectionally trivial once the keys are known.** Pallas is chosen so that
$x\mapsto x^5$ is a permutation, i.e. $\gcd(5,p-1)=1$. Therefore the fifth root is a bijection and the
round map inverts in closed form:

$$
s_{r+1}=(s_r+k_{r\bmod 128}+C_r)^5
\quad\Longleftrightarrow\quad
s_r=(s_{r+1})^{1/5}-k_{r\bmod 128}-C_r.
$$

The round constants $C_r$ are public (they are committed and opened, not secret). So the entire
$8192$-state trace, forward and backward, is determined by the key schedule plus a single anchor
state. The rounds are not a one-way pile of work standing between the attacker and the secret; they
are a reversible ladder, and the only rungs that are hidden are the $128$ repeated keys. The scheme's
security is the secrecy of $128$ field elements, dressed up as the difficulty of $8192$ rounds. Those
are not the same thing, and the literature that makes round count meaningful is about the former
dressed as the latter only when the rounds are genuinely one-way against the *recovery* target. Here
they are not.

## "It is MiMC, and MiMC is well studied at full rounds."

It is not MiMC, in the one respect that decides everything: what is published.

Standard MiMC cryptanalysis bounds the indistinguishability and key-recovery hardness of the
*output* of the permutation after all rounds, from input-output pairs. The carry-forward points in
`mimc-handoff.md` are all of this shape. This scheme publishes none of that. It publishes

$$
nf_d=\sum_j \rho_j^d\,T_j(c\gamma^d),\qquad T_j(c\gamma^d)=\sum_{r=0}^{L-1}s_{j,r}\,\ell_r(c\gamma^d),
$$

where $\ell_r$ are the Lagrange basis polynomials of the order-$8192$ domain. Read the right-hand
side carefully. Each nullifier is a *known, fixed linear functional of the entire state trace*. Not
the final state. Every intermediate state $s_{j,0},\ldots,s_{j,8191}$ appears, weighted by a public
coefficient $\ell_r(c\gamma^d)$. The query does not hide the intermediate states behind the rounds;
it exposes a public linear combination of all of them and repeats the exposure with a new coefficient
vector at every offset $d$.

This is categorically weaker than a MiMC output. The whole reason round count protects a cipher is
that intermediate states are *internal*. An interface that publishes linear functionals of the full
internal trace has thrown that protection away before any cryptanalysis begins. There is no result in
the cited literature, or anywhere I am aware of, that says a periodic-key low-degree-power cipher
remains secure when an attacker is handed an unbounded family of known linear functionals of its
complete state trace. The honest status of the central design decision is not "warrants review." It
is "unsupported, and structurally adverse."

## "A periodic key schedule is fine."

The $128$-element schedule repeats $64$ times across $8192$ rounds. This is the structure modern AO
cryptanalysis flags, not the structure it clears. MiMC's security argument leans on round constants
to break self-similarity, and the slide and key-recovery literature (Bonnetain and successors) exists
precisely because *repeated round keys* create exploitable relations. Here the keys repeat $64$ times
and the constants are public. So the attacker knows that the same $128$ hidden values recur on a fixed
period while the only per-round variation is public. That is the maximally helpful arrangement: it
collapses the secret to $128$ unknowns and stamps a known period onto the trace.

I will not overclaim a concrete slide attack; Bonnetain's results target Feistel and GMiMC structures,
not this exact construction, and the public per-round constants do break literal cycle-to-cycle
identity of the round map. But the burden here runs the other way. A design that wants to claim MiMC's
round-count assurance does not get to also adopt the periodic-key structure that assurance assumes
away, publish the constants that would otherwise mask it, and call the result conservative. The
periodic schedule is a cryptanalytic surface the literature treats as a liability, introduced into the
one place the design can least afford it.

## "The hidden shift and weights defeat sequence recovery."

They defeat the *naive* recovery, and the documents are right that this is their job. Berlekamp-Massey
and Prony read frequencies; secret $c$ and $\rho_j$ make the frequencies $\rho_j\gamma^e$ note-secret
so there is no cheap frequency ladder to read. Granted.

But against a structured solver that already has to treat the trace recurrence as constraints, $c$ and
the four $\rho_j$ are five more unknowns added to $\sim 137$. They change the problem from
"$137$-variable structured system" to "$142$-variable structured system." They are invertible
reparametrizations, not new hardness. The salt-and-shift machinery raises the floor under the cheapest
attack; it does nothing to the ceiling, and the ceiling is what the $8192$ rounds were supposed to be
holding up. The design has spent its cleverness defending against the attack that was never the
dangerous one.

## What is actually being assumed

Strip the framing and the scheme rests on a single, narrow, unliteratured assumption:

> Given many known linear functionals $\sum_r s_{j,r}\ell_r(c\gamma^d)$ of the full state traces of
> four pow5 sequences sharing a $64$-times-repeated $128$-key schedule with public round constants,
> weighted by secret geometric $\rho_j^d$ and sampled at secret-shifted points, it is hard to recover
> a $\sim 142$-element generating secret, where the recurrence is bidirectionally closed-form, the
> algebraic degree saturated after round $\sim 110$, and the round constants are public.

Every clause in that sentence is a feature the design treats as a strength and a solver treats as a
handle. The recurrence is a constraint set, not a wall. The trace exposure is a linear-functional
oracle, not a sealed output. The round count is length, not depth, past saturation. The periodicity is
a known period. The amplitude count $NL$ is an evaluation table of a $142$-dimensional map, not
$32768$ unknowns.

## What this does not claim

Intellectual honesty requires the other column. None of the above is a working attack. The structured
system is large and nonlinear; Gröbner and resultant solving at this scale over a $254$-bit field is
not free, and may be infeasible. Fifth-root inversion still requires the keys, which are not given.
The linear functionals, while known, are evaluated at secret points, so the attacker does not get the
clean Lagrange weights without first pinning $c$. A long pow5 trace may well turn out to resist all of
this. The literature simply does not say it does, because the literature has never looked at this
object.

So the verdict is not "broken." The verdict is that the scheme's confidence is sourced from the wrong
places: from a round count that is mostly length, from an amplitude margin that is an accounting
artifact, and from a body of MiMC results about an interface this design does not use. The actual
security sits on an un-studied assumption about trace-interpolant exposure of a small periodic-key
secret, and that assumption has never been stated plainly, let alone defended.

## What would change the picture

The honest repairs are the expensive ones, and they are the inverse of the comforting framing.

- **Stop publishing functionals of the full trace.** A nullifier derived from a one-way *output* of
  the cipher, or from a per-offset extractor, would restore the protection the rounds were supposed to
  provide. `surface-vs-recovery.md` shows the cost: an extractor destroys the linear accumulator and
  with it single-step range confirmation. That is the real trade the design has been avoiding, and the
  trace-as-spectrum interface is the avoidance.
- **Break the periodicity or shrink it honestly.** Independent per-round keys would cost $8192$
  committed key elements; the $128$-key cycle is a budget compromise that buys its savings out of the
  security argument. Name that price.
- **Size against the true secret.** Replace the $S<NL$ slogan with $S$ against the cost of the
  $\sim 142$-variable structured solve, and commission that estimate. If the margin is real, it should
  survive being measured correctly. If it does not survive, better to learn it from this document than
  from an adversary.

The scheme may be salvageable. The framing is not. The trace as spectrum is the most load-bearing and
least examined decision in the design, and it has been carrying its weight on borrowed credit.
