# Recovery Risk in the Current Pow5 Spectrum Scheme

## Scope

This document analyzes passive recovery risk in the current Tachyon nullifier scheme. The adversary observes published nullifiers for a note and tries to recover enough hidden structure to predict future nullifiers for the same note.

This is not a proof-soundness audit. The proof system must also enforce that the witnessed key material, emitter spectra, query shift, weights, and spend offsets are all correctly bound. Here the question is secrecy and prediction resistance after valid nullifiers become public.

## Protocol summary

The current scheme derives nullifiers from four hidden emitter polynomials. The relevant protocol parameters are

$$
N=4
$$

$$
L=8192
$$

$$
S=16384
$$

Here $N$ is the number of emitters, $L$ is the spectrum length, and $S$ is the nullifier exposure domain size.

The note master key contains six field elements. From this material, the wallet derives:

- an expanded key schedule of length $128$;
- four per-emitter salts;
- a secret query shift $c$;
- secret geometric weight bases $\rho_j$.

The expanded key schedule is generated with a $64$-round pow5 MiMC expansion. Each nullifier emitter polynomial is generated from an $8192$-round pow5 state sequence.

The emitter states satisfy

$$
s_{j,r+1}=(s_{j,r}+k_{r \bmod 128}+C_r)^5
$$

The polynomial $T_j$ is then the interpolant of those states over the order-$8192$ domain:

$$
T_j(\omega^r)=s_{j,r}
$$

The proof does not validate this by naively replaying all $8192$ transitions as separate circuit work. The prover supplies the committed trace and quotient polynomials. Ragu opens the committed objects at Fiat-Shamir challenges and checks the masked quintic recurrence identity as a polynomial identity:

$$
m(z)(T_j(\omega z)-(T_j(z)+O(z))^5)=Q_j(z)(z^L-1)
$$

The offset $O(z)$ is built from the committed constant schedule and one opening of the committed cyclic key polynomial. For each emitter, the proof also checks a boundary identity pinning round $0$. Thus the online proof cost is a small fixed number of polynomial openings and scalar checks, plus quotient-split openings, not $8192$ repeated transition constraints. This makes the in-proof validation much closer to a sumcheck-style quotient check than to an $8192$-round circuit replay.

The native nullifier query at offset $d$ is

$$
nf_d=\sum_{j=0}^{N-1}\rho_j^dT_j(c\gamma^d)
$$

The public output is $nf_d$. The individual emitter evaluations, the shift $c$, the weights $\rho_j$, the salts, and the expanded key schedule are not intended to be public.

## Spectrum-level underdetermination

If the four emitter polynomials were modeled as arbitrary hidden degree-$<8192$ polynomials, then the hidden spectrum-amplitude count would be

$$
NL=4\cdot8192=32768
$$

The maximum number of public offsets for one note is

$$
S=16384
$$

Thus the intended sizing invariant is

$$
S<NL
$$

In the idealized arbitrary-spectrum model, public nullifiers give at most $S$ equations in $NL$ hidden spectrum amplitudes. This leaves many degrees of freedom.

The exponential-sum view makes this sizing intuition explicit. Write

$$
T_j(X)=\sum_{e=0}^{L-1}t_{j,e}X^e
$$

Then

$$
nf_d=\sum_{j=0}^{N-1}\sum_{e=0}^{L-1}(t_{j,e}c^e)(\rho_j\gamma^e)^d
$$

The apparent hidden amplitudes are the $t_{j,e}c^e$, and the public sequence is a sum of exponentials in $d$. The domain is intentionally sized so the note cannot expose enough offsets to determine an arbitrary set of all hidden amplitudes by generic sequence recovery.

## Why the underdetermination argument is incomplete

The real spectra are not arbitrary. They are generated from compact note-bound secrets using Poseidon and pow5 MiMC-style recurrences. Therefore $NL=32768$ is not the entropy of the note.

The actual recovery question is computational:

$$
\text{given many }nf_d\text{ values, predict future }nf_{d'}
$$

The adversary does not need to recover the original note master key. Any compact representation that computes the future sequence would be enough, including:

- the note master key;
- the expanded key schedule plus salts, shift, and weights;
- the four emitter polynomials plus shift and weights;
- another algebraically equivalent representation of the map $d\mapsto nf_d$.

The current scheme therefore rests on a cryptographic assumption: the Poseidon-derived parameters and pow5-derived spectra should be hard to recover or predict from weighted hidden-coset samples.

## Applicable MiMC evidence

The original MiMC analysis is relevant because the emitter is built from repeated low-degree power maps. The relevant attack classes are interpolation, GCD-style algebraic recovery, Gröbner-basis solving, and univariate root-finding.

The important carry-forward points are:

- full-round prime-field MiMC has no known full-round break in the reviewed material;
- the original MiMC round-count argument was motivated by interpolation and GCD attacks;
- improved interpolation work strengthens the warning that reduced-round low-degree designs can be fragile while not invalidating full-round MiMC claims;
- Gröbner-basis and solving-degree work gives useful positive evidence for MiMC-like iterated systems over prime fields;
- reduced-round AO root-finding attacks show that algebraic attacks on these primitives are practical enough to matter.

This evidence is relevant but not decisive for Tachyon. Tachyon uses an $8192$-round trace as an emitter spectrum and exposes off-domain weighted samples of interpolants. That is not exactly the standard MiMC block-cipher or hash-function interface.

## Evidence that should not be over-applied

Some literature is useful as context but should not be presented as a direct attack on the current scheme.

Bonnetain's collision/key-recovery note targets Feistel-MiMC and univariate GMiMC with weak repeated-key schedules. It obtains a slide-like collision/key-recovery property independent of round count. But the note also states that the attack does not appear applicable to MiMC-n/n or MiMC/GMiMC hash functions. For the current Tachyon scheme, this is a key-schedule caution: round constants alone should not be assumed to fix every repeated-key structure. It is not a direct break of the pow5 emitter.

The full-round MiMC attack over binary fields is also not directly applicable to the prime-field setting. Its higher-order differential structure relies on binary-field subspaces that do not exist in the same way over $F_p$.

The improved resultant and FreeLunch line of attacks primarily targets AO permutations with low-degree inverse components and CICO-style sponge security models, especially Griffin, Arion, Anemoi, and Rescue. Those papers help frame the modern algebraic-attack landscape, but they are not direct evidence against plain pow5 MiMC unless a concrete analogous system is built for this construction.

## Main residual risks

### Dedicated algebraic recovery from the nullifier sequence

The public sequence is structured:

$$
y_d=\sum_j\rho_j^dT_j(c\gamma^d)
$$

and the $T_j$ are constrained by pow5 recurrences. A dedicated attack could try to combine many observed $y_d$ values with recurrence constraints to solve for effective key, shift, weight, or emitter representations.

The hidden shift and weighted mixing are intended to make this harder than observing trace states directly. Still, the construction should be regarded as an explicit algebraic assumption, not as an information-theoretic guarantee.

### Cyclic multi-key schedule analysis

The emitter recurrence uses a cyclic $128$-key schedule across $8192$ rounds. This is not the same as the single-key Feistel structure attacked by Bonnetain, but it is also not a fully independent per-round key schedule. The exact cyclic schedule deserves review as part of the construction's cryptanalytic surface.

### State trace as spectrum

The public-facing object is an interpolant of all round states, not just the final MiMC output. Standard MiMC security discussions often focus on encryption or hash outputs. Exposing many algebraic samples of a trace interpolant is a different interface.

The query does not reveal trace states directly. It reveals weighted off-domain samples of hidden interpolants. That helps, but it does not make the interface identical to standard MiMC.

### Shift and weight secrecy

The query shift $c$ and weights $\rho_j$ are part of the secrecy boundary. If they were known or attacker-controlled, the observed sequence would become a more explicit system in the emitter evaluations or coefficients.

They must be note-bound, derived from secret material, and constrained in the proof system rather than freely chosen.

### Proof soundness versus secrecy

The proof system must enforce that the committed emitters really satisfy the pow5 recurrence with the correct expanded key schedule and salts. It must also bind the query shift, weights, and offset to the intended note and lineage state.

A failure there would be a soundness or correctness break. The passive recovery analysis assumes those relations are enforced and asks only whether valid public nullifiers leak enough to predict future values.

## Assessment

The current scheme has residual, assumption-based recovery risk. It is not secure merely because $32768$ apparent amplitudes exceed $16384$ possible public offsets. The real spectra are compactly generated by structured algebraic recurrences.

The favorable point is that the current scheme does not intentionally collapse each emitter into a small product family with simple coefficient identities. Its recovery problem appears closer to attacking a concrete MiMC-style algebraic expansion behind hidden shifted weighted queries than to solving a small closed-form product system.

The appropriate bottom line is therefore cautious: the current pow5 spectrum scheme has a plausible cryptographic expansion story supported by relevant MiMC literature, but Tachyon's exact trace-as-spectrum interface remains a construction-specific assumption that deserves dedicated review.
