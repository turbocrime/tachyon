# Nullifiers

A nullifier is a secret bound at note creation, and published later to destroy the note. Each note has a distinct nullifier per epoch.

To spend a note, a transaction author must prove that no valid nullifier for it has been published in the pool between the note's creation and some anchor[^anchor]. Spending a note publishes two of its nullifiers to the pool, for the anchor epoch and the next epoch, making such a proof impossible to produce afterward.

Pool state is likely to advance between proof creation and mining, so consensus closes the gap by confirming the nullifiers did not enter the pool in the interim.[^tachygrams] The second nullifier allows consensus to tolerate an epoch transition in that interim.

## Derivation

The note's master key $\mathsf{mk}$ is derived from the note's trapdoor $\psi$ and the wallet's nullifier key $\mathsf{nk}$, and should be kept secret.

$$
\mathsf{mk} =
    \mathsf{Poseidon}_\texttt{Tachyon-NfMaster}\!(
        \psi, \mathsf{nk}
    )
$$

Nullifiers come in groups of the sponge rate $r$: one sponge keyed on $\mathsf{mk}$ and the window start $w = e - (e \bmod r)$ squeezes the $r$ consecutive nullifiers starting at epoch $w$.

$$
\mathsf{Poseidon}_\texttt{Tachyon-NfDerive}\!\left(
    \mathsf{mk},\ w
\right) = (\mathsf{nf}_{w},\ \ldots,\ \mathsf{nf}_{w + r - 1})
$$

$\mathsf{nf}_e$ is the member at position $e - w$ in its group. Because $\mathsf{nf}_e$ is a pseudo-random function of $\mathsf{mk}$ and the epoch $e$, distinct epochs yield unrelated nullifiers, and an author cannot steer a nullifier toward a chosen value.

## Binding

$\psi$ is carried in the note and digested into the note commitment $\mathsf{cm}$, alongside the payment key $\mathsf{pk}$, which itself pins $\mathsf{nk}$[^pk]. So $\mathsf{cm}$ fixes both $\psi$ and $\mathsf{nk}$, hence $\mathsf{mk}$, hence the entire nullifier sequence. A note has exactly one nullifier sequence, frozen when its commitment enters the pool as a tachygram.

The proof tree never trusts a freely witnessed nullifier. Wherever a nullifier is consumed, a derivation chain proves in-circuit that it is a genuine sponge output of the note's $\mathsf{mk}$, and binds that derivation to the note by $\mathsf{cm}$.[^derive]

$\psi$ must be unique per note. Two notes that reuse the same $\psi$ share $\mathsf{mk}$ and therefore the same nullifier sequence, so spending one publishes the other's nullifiers.

### Spendable

A spendable tracks an unspent note as the pool advances. It carries the note's current nullifier, its pool anchor, and the note commitment:

$$(\,\mathsf{nf}_e,\;\; \mathsf{anchor},\;\; \mathsf{cm}\,)$$

$\mathsf{nf}_e$ is the nullifier the wallet would publish to spend now, at the lineage's current epoch $e$. Advancing the spendable (a lift) proves every nullifier from epoch $e$ up to the new epoch absent from the pool, then moves $\mathsf{nf}_e$ and the anchor forward together. $\mathsf{cm}$ rides along unchanged, binding the whole lineage to one note, and so to one value: the spend commits to the value inside $\mathsf{cm}$, which the creation stamp proved minted.

A lift advances the current nullifier only to a genuine next derived nullifier, and the next lift's starting nullifier must equal the current one. Because both are PRF outputs, that equality forces the same note and the same epoch, so a lineage cannot skip an epoch or splice in another note.

### Delegation

The holder of $\mathsf{mk}$ can outsource the search for its nullifiers in the pool.[^delegation] It hands a delegate the next window of values $\Delta_{e..e+d}$, which should be the nullifiers $\mathsf{nf}_{e..e+d}$ but which the delegate treats as opaque. The delegate proves them absent from the pool across stamps and epochs, oblivious to $\mathsf{mk}$, $\psi$, $\mathsf{cm}$, and the note, and commits the sequence on the coefficient generators, terminated by a sentinel $1$ one position above the window:

$$\delta = \sum_{i} [\Delta_{e+i}]\,\mathcal{G}_i + \mathcal{G}_d$$

The sentinel keeps every committed sequence nonzero (an empty window is the constant $1$), so $\delta$ is never the identity point, and it pins the window's exact length.

At the lift the wallet binds $\delta$ to genuine derived nullifiers: it proves a contiguous derived range commits to the same sequence, so each $\Delta_{e+i}$ is the real $\mathsf{nf}_{e+i}$. The window is measured in epoch-boundary crossings: $d$ is the crossing count and $\delta$ holds one nullifier per crossing, plus the nullifier of the epoch in progress at the span's tip, which is carried separately because that epoch is not yet complete. The wallet binds the tip too, so the lineage's new current nullifier is itself a genuine derived nullifier rather than a free value.

Re-basing is what lets a window be arbitrary. Any run of nullifiers shifts down to a degree-zero polynomial that stands as a witness on its own, so the wallet can delegate any window from any epoch, and only the wallet, holding the note, can fold the proven absence into the lineage.[^lift]

[^anchor]: [Anchor](./anchor.md) describes the pool state commitment.
[^tachygrams]: See [Tachygrams](./tachygrams.md) for the unified consensus rule covering all published tachygrams.
[^pk]: $\mathsf{pk} = \mathrm{Poseidon}(\text{PK\_DOMAIN}, \mathsf{ak}_x, \mathsf{nk})$ binds $\mathsf{nk}$ into the commitment, so a wrong $\mathsf{nk}$ yields a wrong $\mathsf{cm}$.
[^derive]: The derivation chain and its consumers; see [Proof Tree](./proof-tree.md).
[^delegation]: The delegate composes the absence proofs the wallet later lifts onto its own lineage; see [Proof Tree](./proof-tree.md).
[^lift]: This fold is the `SpendableLift` proof step; see [Proof Tree](./proof-tree.md).
