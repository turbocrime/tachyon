# Recovery Risk in the Current Pow5 Spectrum Scheme

## What this analyzes

The adversary observes published nullifiers for one note and tries to predict its future
nullifiers. This is a secrecy question, not a soundness audit: it assumes the proof system already
enforces that the key material, emitter spectra, query shift, weights, and offsets are correctly
bound, and asks only whether the public values leak enough to extend the sequence.

The reader who wants the bound that governs how many nullifiers a note may safely expose should read
this together with the surface analysis in `surface-vs-recovery.md`; that document shows the recovery
threshold derived here is the same budget that sizes the queryable surface and protects delegation
unlinkability.

## How the scheme works

The protocol parameters are

$$
N=4,\qquad L=8192,\qquad S=16384,
$$

the number of emitters, the spectrum length, and the nullifier exposure domain size.

A note master key of six field elements is expanded by Poseidon and pow5 MiMC into an expanded key
schedule of length $128$, four per-emitter salts, a secret query shift $c$, and secret geometric
weight bases $\rho_j$. The key schedule uses a $64$-round pow5 expansion; each emitter spectrum uses
an $8192$-round pow5 state sequence

$$
s_{j,r+1}=(s_{j,r}+k_{r \bmod 128}+C_r)^5,
$$

and the emitter polynomial $T_j$ is the interpolant of those states over the order-$8192$ domain,
$T_j(\omega^r)=s_{j,r}$.

The proof does not replay all $8192$ transitions. The prover commits the trace and quotient
polynomials, and Ragu checks the masked quintic recurrence as a single polynomial identity at
Fiat-Shamir challenges,

$$
m(z)\big(T_j(\omega z)-(T_j(z)+O(z))^5\big)=Q_j(z)(z^L-1),
$$

where $O(z)$ is built from the committed constant schedule and one opening of the committed cyclic
key polynomial, plus a boundary identity pinning round $0$. Online cost is therefore a small fixed
number of openings and quotient splits, closer to a sumcheck-style quotient check than to an
$8192$-round circuit.

The public output is the nullifier query at offset $d$,

$$
nf_d=\sum_{j=0}^{N-1}\rho_j^d\,T_j(c\gamma^d).
$$

The emitter evaluations, the shift $c$, the weights $\rho_j$, the salts, and the key schedule are all
secret.

## The sizing intuition, and why it is not the whole story

Model the emitters first as arbitrary hidden polynomials of degree $<L$. Then the hidden
spectrum-amplitude count is $NL=32768$, while a note exposes at most $S=16384$ offsets, so the
design maintains

$$
S<NL.
$$

The exponential-sum view makes this concrete. Writing $T_j(X)=\sum_e t_{j,e}X^e$,

$$
nf_d=\sum_{j}\sum_{e}(t_{j,e}c^e)(\rho_j\gamma^e)^d,
$$

a sum of $NL$ exponentials in $d$ with frequencies $\rho_j\gamma^e$. With fewer public offsets than
hidden amplitudes, generic sequence recovery cannot pin an arbitrary amplitude set.

The catch is that the spectra are not arbitrary. They are generated from compact note secrets by
Poseidon and pow5 recurrences, so $NL$ overstates the note's entropy. The real question is
computational: given many $nf_d$, predict $nf_{d'}$. An attacker does not need the master key; any
compact representation that reproduces $d\mapsto nf_d$ suffices, whether the key schedule plus salts,
shift, and weights, the four emitter polynomials plus shift and weights, or any equivalent model. The
scheme therefore rests on a cryptographic assumption: the Poseidon-derived parameters and
pow5-derived spectra are hard to recover from weighted hidden-coset samples.

## What the MiMC literature does and does not establish

The emitter is built from repeated low-degree power maps, so the relevant attack classes are
interpolation, GCD-style recovery, Gröbner-basis solving, and univariate root-finding. The useful
carry-forward points are that full-round prime-field MiMC has no known full-round break in the
reviewed material, that MiMC's round-count argument was itself motivated by interpolation and GCD
attacks, that improved interpolation work sharpens the warning against reduced-round low-degree
designs without invalidating full-round claims, and that Gröbner-basis and solving-degree results
give positive evidence for MiMC-like systems over prime fields.

Three lines should not be over-applied. Bonnetain's collision and key-recovery note targets
Feistel-MiMC and univariate GMiMC with weak repeated-key schedules and explicitly does not appear to
apply to MiMC-n/n or MiMC/GMiMC hash functions; for us it is a key-schedule caution, not a break of
the pow5 emitter. Full-round MiMC attacks over binary fields rely on subspace structure absent over
$F_p$. The improved-resultant and FreeLunch line targets AO permutations with low-degree inverse
components under CICO models (Griffin, Arion, Anemoi, Rescue), so it frames the modern landscape
without bearing directly on plain pow5 MiMC unless a concrete analogous system is built.

The gap between this evidence and Tachyon is that the literature studies standard block-cipher or
hash interfaces, whereas Tachyon exposes off-domain weighted samples of an $8192$-round trace
interpolant. That is a different interface and is the construction-specific assumption that needs
dedicated review.

## Residual risks, in priority order

1. **Dedicated algebraic recovery from the sequence.** The public $y_d=\sum_j\rho_j^dT_j(c\gamma^d)$
   is structured, and the $T_j$ obey pow5 recurrences. A dedicated attack could combine many $y_d$
   with the recurrence constraints to solve for effective key, shift, weight, or emitter
   representations. The hidden shift and weighting are what make this harder than reading trace
   states directly, but the resistance is an algebraic assumption, not an information-theoretic
   guarantee.
2. **The cyclic key schedule.** The $128$-key schedule cycled across $8192$ rounds is neither the
   single-key Feistel structure Bonnetain attacks nor a fully independent per-round schedule. Its
   exact structure is part of the cryptanalytic surface and deserves review.
3. **Trace-as-spectrum exposure.** The public object is an interpolant of all round states, not just
   a final output. The query reveals weighted off-domain samples rather than the states themselves,
   which helps, but it remains a nonstandard interface.
4. **Shift and weight secrecy.** If $c$ or the $\rho_j$ were known or attacker-controlled, the
   observed sequence would become a far more explicit system in the emitter evaluations. They must
   be note-bound, secret-derived, and proof-constrained.

## Assessment

The scheme is not safe merely because $32768$ apparent amplitudes exceed $16384$ offsets; the
spectra are compactly generated, so that count is not entropy. Its favorable property is that it does
not collapse each emitter into a small family with simple coefficient identities, so its recovery
problem resembles attacking a concrete MiMC-style expansion behind hidden weighted queries rather
than solving a small closed-form system. The honest bottom line is that the scheme has a plausible
cryptographic-expansion story supported by MiMC literature, with one construction-specific
assumption, the trace-as-spectrum interface, that warrants dedicated cryptanalysis.
