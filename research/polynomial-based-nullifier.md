# Polynomial-based Nullifier

$$
\def\F{\mathbb{F}}
\def\G{\mathbb{G}}
\def\P{\mathcal{P}} % Prover
\def\V{\mathcal{V}} % Verifier
\def\acc{\mathsf{acc}} % accumulator
\def\v#1{\mathbf{#1}} % vec
\def\dp#1#2{\left\langle #1, #2 \right\rangle} % dot product
\def\sample{\overset{\$}{\leftarrow}} % random sample
\def\iseq{\overset{?}{=}} % is equal check
\def\com{\mathsf{Commit}} % commit
\def\PRF{\mathsf{PRF}}
\def\PRP{\mathsf{PRP}}
\def\pk{\mathsf{pk}} % payment key
\def\rcm{\mathsf{rcm}} % trapdoor for cm
\def\nf{\mathsf{nf}} % nullifier
\def\nk{\mathsf{nk}} % nullifier key
\def\cm{\mathsf{cm}} % commitment
$$

### Background

Quoting from the Tachyon
[writeup](https://github.com/alxiong/tachyon/blob/book-alex/book/src/revisit.md)
(or its [PR](https://github.com/tachyon-zcash/tachyon/pull/129)):

A Tachyon note is:

$$
\mathsf{Note} := (\pk, v, \psi, \rcm) 
$$

where $\pk$ is the payment key, $v$ is the value of the note, 
$\psi$ is pseudo-random note identity that binds to the note nullifier value as an input to its derivation,
and $\rcm$ is a random commitment trapdoor.

The ideal functionality for an epoched nullifier is a deterministic function:

$$
\nf_e = \mathsf{KDF}(\nk, \psi, e)
$$

whose outputs are indistinguishable from random bytes.
Such an $\nf_e$ binds to both the spending authority (via $\nk$) and the underlying note (via its per-note trapdoor $\psi$),
while remaining unlinkable across epochs to anyone without $\nk$.

The writeup also explains a **GGM-based nullifier** whose derivation requires walking a tree where each step involves a Poseidon hash function.
The construction details are irrelevant thus skipped here.
The screenshot below is merely a visual reminder for the initiated.

![Screenshot 2026-06-30 at 9.11.47 PM](https://hackmd.io/_uploads/HJ-sxSbQzl.png)

The main takeaway is: a single nullifier derivation already saturates the circuit capacity for a PCD step!

<details>
<summary>Calculation</summary>
    
The GGM tree size is determined by how large of the epoch space do weant to support.
A depth-$14$ tree implies the largest epoch value being $2^{14}-1$. Assuming 1 day/epoch, this translates to 45 years in the future which is reasonable.
A full root-to-leaf walk of such tree requires $14$ Poseidon hashes.
    
Step circuit size (`max_mul_gates`) is $n=2^{11}=2048$. Since our constraint system allows $4n$ linear constraints, this budget is overly abundant and we only focus on multiplication constraints.
Step capacity for Poseidon is $7$ ([see here](https://github.com/tachyon-zcash/ragu/pull/720)) as per-permutation gate cost is $288$.
    
With a mixed-arity optimization of the tree (see Tachyon writeup), where the arity is higher towards the root and binary towards the leaf, we can cut down the depth to 7, thus fit a full derivation in a single step.
    
</details>

Ideally, we want to fit more (at least two) nullifier derivation in a single step.
For example, deriving both $\nf_e$ and $\nf_{e+1}$ for the spending epoch $e$ in a single step is highly desirable.
Therefore, the challenge is to find alternative more circuit-friendly nullifier constructions.

The high-level idea is to construct a degree-$(n-1)$ polynomial $f(X)$ such that:

- $\nf_e = f(e)$, supporting epoch range $[1, n]$ (take $n=2^k$ for a reasonable $k=14$ which is $\approx 45$ years assuming a 1 day/epoch pace)
- Highly efficient to evaluate $f(X)$: $O(\log{n})$ work only (we will see why after attempt 1 below)
- Given any set of evaluation points $S \subseteq [n]$ and their evaluations $\{f(i)\}_{i\in S}$, **any evaluation outside the set $f(j\notin S)$ is indistinguishable from random**
  - strictly stronger requirement than "cannot compute $f(j)$": semantic security is necessary for spend unlinkability property
  - we will discuss what statistical and computational indistinguishability demands respectively

This alternative is a promising direction because proving $\nf_e$ derivation is now simply an evaluation claim,
which can be either proven directly in circuit (only field ops) or piggyback on the "PolyQuery Oracle" our PCD proof system natively supports (low circuit cost).

### Threat Model

We discuss security from the perspective of recipients whom we address to as "users".
Senders and syncing services (OSS) are untrusted.
Here are the assumptions/setup:

- $\psi, \rcm$: picked by the sender
- $\nk$: privately known to the user
- OSS can derive nullifiers for a finite range of delegated epochs. They cannot locate/link the note commitment $\cm$ or future nullifiers outside the range.
- malicious users try to double-spend by publishing $\nf_e' \neq \nf_e$ for the same note in any epoch $e$ that both pass the derivation integrity check

### Attempt 1

- User randomly samples a $f(X)$ of bounded degree, commits to it and sends $\cm_f$ to the sender.
- Sender prepares the Output note by setting $\psi = \mathsf{Extract}(\cm_f)$. Effectively, the $\cm$ commits to the nullifier polynomial.
  - user wallet rejects incoming note with unknown/wrong/repeated $\psi$
- OSS directly receives $\{\nf_i\}$ for the delegated range

Pros:

- The circuit cost is minimum: load the note opening as secret witness, re-commit to $\cm$, then piggyback a PCS eval claim to the PolyQuery oracle.
- Proving multiple $\nf_e$ is practically free since querying multiple points on an already committed polynomial in our PolyQuery oracle incurs negligible overhead
- Meet stats. indist. requirement

Problems:

1. Every new note requires user involvement (OOB), a UX nightmare even if user preload some sampled polynomials.

Lessons:

1. sender picked

### Attempt 2

Consider the following structured polynomial:

$$
f(X) = \prod_{i=0}^k (X^{2^i} + b_i)
= (X + b_0)\cdot (X^2 + b_1)\cdot (X^4 + b_2)\cdot\ldots\cdot (X^{2^k} + b_k)
$$

where $b_0 = \PRF_\nk(\psi), b_i = \PRP(b_{i-1})$.

The concrete instantiation doesn't requires $k$ permutation (PRP) invocation

Pros:

- $O(\log n)$ evaluation cost


Problem: linear dependence
TODO: show an example

### Attempt 3

We fix the linear dependence with a small modification:

$$
f(X) = \prod_{i=0}^k (a_i X^{2^i} + b_i)
$$

where

### Attempt 4

Define an MiMC round function $F_i(x) = (x \oplus k \oplus c_i)^\alpha$ where $k$ is a key, $c_i$ are round constant (fixed at setup), and $\alpha$ is usually a small value such that $\gcd(\alpha, p-1)=1$ for a finite field $\F_p$.
While the original MiMC paper set $\alpha=3$ for binary field $\F_{2^n}$, we care about large prime field typically with $p \equiv 1\pmod 3$ (such as BLS12-381, Pasta curves), thus we pick $\alpha=5$ instead.

$$
\begin{cases}
k = \PRF_\nk(\psi) \\
\nf_e =  (F_{r-1} \circ F_{r-1} \circ\ldots\circ F_0)(e) \oplus k
\end{cases}
$$

where $r$ is the total number of rounds.

TODO: draw a simple diagram

TODO: go through stats. analysis of how large r needs to be. Also explain alpha doesn't affect r

