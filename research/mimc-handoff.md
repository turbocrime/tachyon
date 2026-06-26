# Context Handoff — Investigating a MiMC Scheme vs. a Generic Polynomial-Expansion Scheme

**Provenance:** Compiled from a literature review focused on **prime-field** MiMC cryptanalysis. All links are canonical (IACR ePrint / ToSC, publisher DOIs, or author archives) and were live as of compilation. Treat technical claims as starting points to verify, not gospel.

**Scope assumption:** The downstream investigation concerns a *use* of a MiMC scheme (most likely Feistel-MiMC / MiMCHash in a zk-SNARK or MPC setting) over a **prime field** `F_p`, and a comparison against another **polynomial-expansion scheme** (either a named arithmetization-oriented (AO) primitive, or an abstract iterated-polynomial construction). Both readings are handled below — see §5.

---

## 0. TL;DR for the receiving agent

- **Prime-field MiMC has never been broken at full rounds.** The dramatic full-round key-recovery attack from 2020 is **binary-field-only** and is structurally inapplicable over `F_p` (there are no nontrivial `F_p`-subspaces to exploit). Do not let that result, or the flashy 2024 full-round breaks (FreeLunch et al.), bleed into the prime-field threat model — those 2024 breaks hit MiMC's *cousins* (Anemoi, Arion, Griffin), which use low-degree-**inverse** S-boxes, not MiMC's plain power map.
- **The real prime-field attack surface is purely algebraic/univariate:** interpolation, GCD, Gröbner-basis on the iterated polynomial system, and (recently) CICO / univariate root-finding. These set the round count; they do not currently break the recommended parameters.
- **One field-independent caveat:** Bonnetain's slide-style key recovery breaks Feistel-MiMC / univariate GMiMC in `~2^{n/2}` by exploiting the **weak key schedule** — independent of the round function and round count, so it *does* apply to prime-field Feistel variants. Check the key schedule of whatever instance you're handed.
- **Before deep work, pin down:** which MiMC variant, the prime `p` and S-box exponent `d`, the target security level, the proof system / arithmetization metric (R1CS, Plonk, AIR), and exactly what the "generic polynomial-expansion scheme" is. See §7.

---

## 1. What MiMC is (the structural facts you'll reason over)

MiMC ("Minimal Multiplicative Complexity") is built by iterating a **low-degree power map** over a large field `F_q` (`q` prime or `2^n`).

- **Block cipher MiMC-n/n:** round `i` computes `x ↦ (x + k + c_i)^d`, with round constants `c_i` (`c_0 = 0`), a single key `k` added each round, and a final key addition. The canonical exponent is `d = 3`, requiring `gcd(d, q−1) = 1` so the map is a permutation.
- **Degree growth:** the univariate polynomial representing `r` rounds has degree `d^r` (i.e., it **triples per round** for `d = 3`). This single fact drives the cost of interpolation and Gröbner-basis attacks — it is *the* number to compare against any other scheme.
- **Round count:** designers recommend `r = ceil(n · log_d 2)` rounds (`≈ ceil(n / 1.585)` for `d = 3`, with `n ≈ log2 q`). This was derived specifically from resistance to **interpolation** and **GCD** attacks — not from a wide-margin diffusion argument.
- **Feistel-MiMC (= MiMC-2n/n):** a 2-branch Feistel using the same `(· + k + c_i)^d` round function. This is the permutation typically plugged into a **sponge** to build **MiMCHash**, and it's what most ZK toolkits actually deploy for hashing.
- **No state expansion / no MDS layer** in the plain block cipher: it operates on a single field element (Feistel variants on two). There is no linear diffusion matrix — diffusion comes entirely from the high algebraic degree. This is the key structural contrast with SPN-style AO primitives.
- **Prime-field exponent caveat:** when `gcd(3, p−1) ≠ 1`, the smallest valid `d > 2` is used instead (commonly `d = 5`). E.g. on the BN254 / `alt_bn128` scalar field, `3` is not coprime to `p−1`, so deployments use `x^5`.

---

## 2. Concrete deployment anchor (the most likely "use")

If the "use" under investigation is a Ethereum/zk-SNARK MiMC hash, the reference implementation pattern is **MiMC + Miyaguchi–Preneel** (block cipher → one-way compression → sponge/hash):

- Field: BN254 scalar field, `p = 21888242871839275222246405745257275088548364400416034343698204186575808495617`
- S-box: `x^5` (since `gcd(5, p−1) = 1` for this `p`)
- Construction: MiMC permutation under Miyaguchi–Preneel for hashing; fixed key/IV for the first block.
- Reference: <https://github.com/HarryR/ethsnarks/wiki/MiMC-and-Miyaguchi%E2%80%93Preneel-OWF>

Confirm the actual instance's `p`, `d`, round count, and whether it's the keyed cipher, the permutation, or the hash — the threat model differs across these.

---

## 3. Cryptanalytic state over prime fields (the carried finding)

**Status: no full-round break.** The relevant attacks, and what each does:

- **Interpolation attack** — reconstruct the encryption polynomial without the key from `~d^r + 1` plaintext/ciphertext pairs. Drives the round-count lower bound. Li–Preneel improved the low-memory variant but it does **not** affect full-round security claims.
- **GCD attack** — represent the cipher as a univariate polynomial in the key and GCD against the field equation `y^q − y` (or against a second plaintext/ciphertext polynomial). This is essentially the strongest generic algebraic attack, and recent work shows Gröbner-basis attacks collapse back to roughly this cost.
- **Gröbner-basis on the iterated polynomial system** — model each round as a degree-`d` equation plus the field equation; solving complexity is governed by the solving degree / Castelnuovo–Mumford regularity. Steiner (2024) gives the first *proven* bounds and concludes MiMC keeps `≥ 128` bits across field sizes.
- **CICO / univariate root-finding** — the 2024-era AO attack technique. Bariant et al. (2022) used univariate root-finding to solve many of the Ethereum Foundation's *reduced-round* Feistel-MiMC challenges, but not the full primitive.
- **Key-schedule slide (Bonnetain)** — `~2^{n/2}` key recovery on Feistel-MiMC / univariate GMiMC from the weak (single-key) schedule; round-function- and round-count-independent, hence **field-independent**.

**What does NOT apply over `F_p`:** the higher-order-differential / slow-degree-growth attack that broke full-round binary-field MiMC. Reason: the only `F_p`-subspaces are `{0}` and `F_p`, so the higher-order distinguisher has nowhere to live.

---

## 4. Carry-forward references (the load-bearing papers)

Ordered by relevance to prime-field MiMC. Each line: what it gives you, and its bearing.

1. **Albrecht, Grassi, Rechberger, Roy, Tiessen — "MiMC: Efficient Encryption and Cryptographic Hashing with Minimal Multiplicative Complexity"** (ASIACRYPT 2016). The design + the designers' own algebraic analysis (interpolation, the new GCD attack, invariant-subfield). *Baseline / spec.* — <https://eprint.iacr.org/2016/492>
2. **Albrecht, Cid, Grassi, Khovratovich, Lüftenegger, Rechberger, Schofnegger — "Algebraic Cryptanalysis of STARK-Friendly Designs: Application to MARVELlous and MiMC"** (ASIACRYPT 2019). The foundational Gröbner-basis treatment for prime fields; the framework everything later builds on. *Primary prime-field analysis.* — <https://eprint.iacr.org/2019/419>
3. **Li, Preneel — "Improved Interpolation Attacks on Cryptographic Primitives of Low Algebraic Degree"** (SAC 2019). Low-memory interpolation; tightens round counts. *Pressure test; does not break full rounds.* — <https://eprint.iacr.org/2019/812>
4. **Steiner — "Solving Degree Bounds for Iterated Polynomial Systems"** (IACR ToSC 2024). First *proven* Gröbner-basis complexity bounds for the MiMC family; concludes `≥ 128` bits. *Strongest positive security statement.* — <https://arxiv.org/abs/2310.03637>
5. **Bariant, Bouvier, Leurent, Perrin — "Algebraic Attacks against Some Arithmetization-Oriented Primitives"** (IACR ToSC 2022/3). Univariate root-finding solves reduced-round Ethereum-challenge Feistel-MiMC instances. *Closest thing to a live prime-field attack on a MiMC variant.* — <https://tosc.iacr.org/index.php/ToSC/article/view/9850>
6. **Bonnetain — "Collisions on Feistel-MiMC and univariate GMiMC"** (2019). `2^{n/2}` slide-style key recovery from the weak key schedule; field- and round-independent. *Applies to prime-field Feistel-MiMC; check the key schedule.* — <https://eprint.iacr.org/2019/951> (also <https://inria.hal.science/hal-02400343>)

**Context / "you'll see these but they don't break prime-field MiMC":**

7. **Eichlseder, Grassi, Lüftenegger, Øygarden, Rechberger, Schofnegger, Wang — "An Algebraic Attack on Ciphers with Low-Degree Round Functions: Application to Full MiMC"** (ASIACRYPT 2020). Full-round break **over `F_2^n` only**; explicitly does not affect prime fields. *Know it to rule it out.* — <https://eprint.iacr.org/2020/182>
8. **Roy, Andreeva, Sauer — "Interpolation Cryptanalysis of Unbalanced Feistel Networks with Low Degree Round Functions"** (SAC 2020). Prime-field interpolation extended to UFNs — targets **GMiMC**, not MiMC-n/n. *Relevant if the variant is generalized-Feistel.* — <https://doi.org/10.1007/978-3-030-81652-0_11>
9. **Bariant, Boeuf, Lemoine, Manterola Ayala, Øygarden, Perrin, Raddum — "The Algebraic FreeLunch"** (CRYPTO 2024). Full-round breaks of **Anemoi, Arion, Griffin** (low-degree-inverse S-boxes). *Does NOT target MiMC — the common point of confusion.* — <https://eprint.iacr.org/2024/347>
10. **"The Algebraic CheapLunch: Extending FreeLunch Attacks Beyond CICO-1"** (2025). Multi-output CICO extension of FreeLunch. *Same family scope; watch for any MiMC-applicable corollaries.* — <https://eprint.iacr.org/2025/2040>
11. **"Improved Resultant Attack Against Arithmetization-Oriented Primitives"** (2024/2025). Resultant-based CICO solving, complementary to FreeLunch. *Methodology reference for the AO attack landscape.* — <https://doi.org/10.1007/978-3-032-01901-1_11>

---

## 5. Comparison framework — MiMC vs. the polynomial-expansion scheme

This is the core of the handoff. For each axis: what MiMC is, what to determine for the comparison scheme, and why it changes the analysis.

| Axis | MiMC | Determine for the comparison scheme | Why it matters |
|---|---|---|---|
| **Algebraic form** | Univariate iterated power map `(x+k+c)^d` | Is it univariate or wide-state multivariate? SPN, Feistel, or other? | Decides whether the relevant attack is univariate (GCD/interpolation) or multivariate CICO/Gröbner. |
| **Degree growth / round** | `×d` (×3 for `d=3`); univariate degree `d^r` | Per-round degree multiplier and the post-`r`-round degree | Directly sets interpolation cost and Gröbner solving degree — the headline comparison number. |
| **S-box family** | Low-degree **power** map `x^d` | Power map `x^d`, low-degree-**inverse** `x^{1/d}`, or lookup/hybrid? | Low-degree-inverse S-boxes are what FreeLunch/resultant attacks exploit; power maps largely are not. |
| **State width / diffusion** | Width 1 (Feistel: 2); **no MDS layer** | State size, and whether there's a linear/MDS diffusion layer | Wide-state + MDS shifts the attack to CICO and changes the round-count argument entirely. |
| **Native field** | `F_q`, prime or `2^n` (`gcd(d, q−1)=1`) | Prime vs binary; the specific modulus | Binary-field higher-order-differential attacks vanish over `F_p`; modulus affects exponent choice. |
| **Key schedule** | Single key added each round (weak) | Trivial, cyclic, or full schedule? | Trivial/cyclic schedules enable slide attacks (cf. Bonnetain) independent of rounds. |
| **Security-argument basis** | Now has **proven** solving-degree bounds (Steiner) | Heuristic/experimental estimate or proven bound? | A proven bound is far stronger evidence than extrapolated experiments; weight conclusions accordingly. |
| **Round-count derivation** | From interpolation + GCD resistance | Which attacks set the rounds, and what margin? | Tells you which attack to stress and whether the margin is thin. |
| **Mult. complexity profile** | Minimal multiplications; deep low-width circuit | Constraint count in R1CS / Plonk / AIR | The whole reason these schemes exist; the actual efficiency comparison lives here. |

**Two readings of "generic polynomial-expansion scheme":**
- *If it's a named AO primitive* (Poseidon, Rescue-Prime, etc.) → use the family map in §6 to fetch its spec and slot it into the table.
- *If it's an abstract iterated-polynomial construction* → the axes still apply unchanged; the critical unknowns to extract from its definition are the **per-round degree multiplier**, the **state width / presence of a diffusion layer**, and the **field**. Everything else follows from those three.

---

## 6. Comparison-scheme family map (if it's a named AO primitive)

Likely candidates, with the one structural feature that matters most for the comparison:

- **Poseidon / Poseidon2** — SPN over `F_p`, `x^d` S-box, full + partial rounds, MDS diffusion. (Power-map S-box, like MiMC, but wide-state.)
- **Rescue / Rescue-Prime** — alternating `x^d` and `x^{1/d}` S-box layers over `F_p`. (Mixes power and *inverse* maps — partially in FreeLunch/resultant scope.)
- **Anemoi**, **Griffin**, **Arion** — `F_p` permutations using low-degree-**inverse** components; **broken at full rounds by FreeLunch (2024)**. (The cautionary contrast: these fell, MiMC did not.)
- **Ciminion** — `F_p` stream-cipher-style with a low-degree round function; attacked via tailored equation systems.
- **GMiMC** — generalizes MiMC-2n/n to generalized-Feistel networks; subject to the UFN interpolation attack (ref #8) and Bonnetain's slide attack.
- **HadesMiMC / Hades** — the SPN-with-partial-rounds strategy underlying Poseidon; covered by Steiner's proven bounds alongside MiMC.

**Family catalog with specs and per-primitive links** (single best exploration entry point): STAP Zoo — <https://stap-zoo.com/all-stap-primitives/>. Pull the exact spec + cryptanalysis links for whichever scheme turns out to be the comparison target there.

---

## 7. Open variables to pin down before deep work

1. **MiMC variant:** keyed block cipher, bare permutation, Feistel-MiMC, or MiMCHash (sponge)? Threat model differs.
2. **Field & S-box:** the prime `p` and exponent `d` (`3`? `5`? other?).
3. **Round count** of the actual instance vs. the `ceil(n · log_d 2)` recommendation — any reduced-round usage?
4. **Key schedule** (for keyed/Feistel use) — is it the weak single-key schedule? → Bonnetain applies.
5. **Target security level** (128-bit? other?) — sets which solving-degree bound is the binding constraint.
6. **Arithmetization metric** for the efficiency comparison: R1CS, Plonk/Plonkish, or AIR (STARK)? Constraint counts differ per metric.
7. **The comparison scheme's identity** — named primitive (→ §6) or abstract construction (→ §5, extract degree-multiplier / width / field).
8. **What "compare" means here** — security margin, prover/circuit cost, attack-surface breadth, or all three? Different deliverables.

---

## 8. Link index

**MiMC core / cryptanalysis**
- MiMC design (ASIACRYPT 2016): <https://eprint.iacr.org/2016/492>
- Algebraic Cryptanalysis of STARK-Friendly Designs (ASIACRYPT 2019): <https://eprint.iacr.org/2019/419>
- Improved Interpolation Attacks (SAC 2019): <https://eprint.iacr.org/2019/812>
- Solving Degree Bounds for Iterated Polynomial Systems (ToSC 2024): <https://arxiv.org/abs/2310.03637>
- Algebraic Attacks against Some AO Primitives (ToSC 2022/3): <https://tosc.iacr.org/index.php/ToSC/article/view/9850>
- Collisions on Feistel-MiMC and univariate GMiMC (2019): <https://eprint.iacr.org/2019/951>
- Full MiMC binary-field attack (ASIACRYPT 2020): <https://eprint.iacr.org/2020/182>
- Interpolation Cryptanalysis of UFNs / GMiMC (SAC 2020): <https://doi.org/10.1007/978-3-030-81652-0_11>

**Wider AO attack landscape**
- The Algebraic FreeLunch (CRYPTO 2024): <https://eprint.iacr.org/2024/347>
- The Algebraic CheapLunch (2025): <https://eprint.iacr.org/2025/2040>
- Improved Resultant Attack Against AO Primitives (2024/2025): <https://doi.org/10.1007/978-3-032-01901-1_11>

**Deployment & family reference**
- EthSnarks MiMC + Miyaguchi–Preneel: <https://github.com/HarryR/ethsnarks/wiki/MiMC-and-Miyaguchi%E2%80%93Preneel-OWF>
- STAP Zoo (AO primitive catalog): <https://stap-zoo.com/all-stap-primitives/>
