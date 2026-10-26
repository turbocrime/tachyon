# Poseidon in Tachyon: uses and risk areas (v2, with #233)

**Current as of** `main` at `6cdaebcc` (#233 merged as `eeddbb77`, #234 merged as `6cdaebcc`) and the unmerged `ragu-mock-adopt` branch at `f09bb21c`. Updated 2026-10-26. Code citations are at `6cdaebcc` unless they carry a `pending:` prefix, which means `ragu-mock-adopt` at `f09bb21c`. The cryptanalysis sources were last read on 2026-10-16 and are not refreshed here. Text marked **Superseded** was true of an earlier commit and is kept with the reason it no longer holds. Text marked **Update** is new in this revision.

*Superseded header (2026-10-19). This version adds the dynamic fee of PR #233 (branch `dynamic-fee` at `b9e583ff`, based on `7acbdf59`). Code citations are at `b9e583ff`. The merged #233 differs from that branch (see [What merged #233 changed](#what-merged-233-changed)), so many step names and line numbers below were refreshed in this revision. Paths are relative to the repository root. A `ragu:` prefix means the checkout at `~/.cargo/git/checkouts/ragu-2ccfa101a62981f4/0881656`, the revision `crates/tachyon/Cargo.toml` pins (unchanged on `main` and on `ragu-mock-adopt`). A `ragu-local:` prefix means the local ragu working tree at `~/Developer/github.com/tachyon-zcash/ragu`, branch `poly-query-3-query-harder`. A `ragu-mock:` prefix means `~/.paseo/worktrees/3c4hpyde/mock-closer-to-real` at `8a548a4a`, the tree `ragu-mock-adopt` patches in through `Cargo.toml:231-237`.*

This document lists every place Tachyon hashes with Poseidon, the property each place needs from the hash, and what an attacker gains when that property fails.

## What #233 changes

PR #233 adds a max fee note that a wallet signs once, and a FeeStamp that sets the fee later (`book/src/fee.md`).
- **Two new Poseidon functions.** `fee_blind` derives the max fee note's value commitment blind from its opening. `fee_digest` puts the fee descriptor into the action accumulator.
- **A third way to create a note.** FeeStamp computes the fee change note's commitment with `note_commitment` and adds it to the tachygram set. **Superseded** as to the step name. FeeFuse and FeeSeed compute it (`stamp/proof/stamp.rs:607`, `705`).
- **A split between author and custody.** The book lets "anyone with the max fee note's opening" set the fee (`book/src/fee.md:199-200`). **Superseded** as to the citation. The merged `book/src/fee.md` has 148 lines and no such sentence. The split itself holds. The planner holds the max fee note (`book/src/authorization.md:295-299`), custody derives cv_maxfee from the opening before signing (`authorization.md:329`), and the prover applies FeeFuse with the opening and the fee (`book/src/fee.md:116-119`, `authorization.md:385-391`).

The changes add R13 (the fee change note's owner) and R14 (the fee descriptor). They extend R1, R7, R10 and R11. The P1 set is unchanged.

### What merged #233 changed

The merged PR (`eeddbb77`) differs from the reviewed branch `b9e583ff` (`git diff b9e583ff eeddbb77` touches 28 files). No Poseidon function changed its inputs. The differences that matter here are the following.

- **Steps.** OutputStamp is now OutputAction (`stamp/proof/stamp.rs:105`) and SpendStamp is now SpendAction (`stamp.rs:178`). Both emit an `Actions` header (`stamp.rs:44`). ActionMerge (`stamp.rs:329`) and ActionLift (`stamp.rs:473`) work on `Actions`. FeeFuse (`stamp.rs:521`) turns `Actions` into a `Stamp`. FeeSeed (`stamp.rs:653`) proves the zero fee of a zero-action bundle, and an innocent aggregate uses it (`book/src/proof-tree.md:91`). StampMerge and StampLift still act on `Stamp`.
- **Anchors.** OutputAction and FeeSeed take the anchor as a free witness (`stamp.rs:113`, `661`). FeeFuse threads it from the left `Actions` (`stamp.rs:644`). Nothing in the fee steps folds an anchor.
- **Notes.** A note value may be zero (`book/src/notes.md`, "0 ≤ v"). The fee change note can therefore have value zero, and its tachygram is still published (`book/src/fee.md:66-68`).
- **Tests.** `fee_descriptor_mismatch_is_rejected`, cited under R13 in v2, no longer exists. The fee tests are in `crates/tachyon/tests/integration/fee.rs` (`fee_fuse_binds_its_sets` at `:118`, `fee_seed_binds_its_singletons_and_header` at `:710`). No merged test substitutes a second opening for the max fee note.

### What #234 changed

#234 (`6cdaebcc`, "poseidon domain strings") moves every domain tag into the sponge capacity.

- **Layout.** `tagged_sponge` builds a state with the rate at zero and the capacity element at `Fp::from_u128(u128::from_le_bytes(domain))`, resumes the ragu sponge from it, and absorbs the data only (`digest/poseidon.rs:44-70`). Every one of the fourteen functions goes through `hash` or `tagged_sponge` (`poseidon.rs:72-75`).
- **The node is tagged.** `evidence_tree_node` takes the domain `Tachyon-EvidNode` (`poseidon.rs:229`, `270-272`). It was the only untagged function in v2.
- **Permutation counts.** `note_commitment`, `pad_tachygram`, `action_digest` and `anchor_next_stamp` fall from two permutations to one. `evidence_tree_leaf` falls from three to two. The other nine keep one (`book/src/proof-tree.md:286-296`, `369-374`).
- **No length term.** The capacity is the tag alone. The construction reviewed in `poseidon-capacity-review.md` (`177ae3e7`) put `tag + L * 2^128` there, and it added a layout test against an independent permutation. Neither landed. Each tag is used at one arity today, so no two inputs under one tag differ by trailing zeros (R15).
- **No test pins the layout.** `digest/poseidon.rs` has no test module, and no integration test hard-codes a Poseidon output.

### Delta against v2 at a glance

**Update.**

| item | v2 | now |
|---|---|---|
| Poseidon functions | 14 | 14, none added or removed |
| tagged by absorbing the tag first | 13 | 0 (all 14 use the capacity) |
| untagged | `evidence_tree_node` | none. **R11 is superseded** |
| permutation calls | `note_commitment`, `pad_tachygram`, `action_digest`, `anchor_next_stamp` use 2, `evidence_tree_leaf` uses 3 | 1, 1, 1, 1 and 2 |
| step names | OutputStamp, SpendStamp, FeeStamp | OutputAction, SpendAction, FeeFuse, FeeSeed |
| final-call free words, R1 inflation and R2 | `psi` | `rcm`, `pk` and `psi` on the output side (R1 double spend and R4 keep `rcm` and `psi`) |
| final-call free word, R5 | none | the predecessor anchor |
| R5 priority | P2 | P1 (rubric amended, see Triage) |
| step challenges on `main` | described as Poseidon digests (`ragu-local`) | BLAKE2b in the pinned mock (`ragu:src/mock/ctx.rs:33-52`) |

## Summary

- Tachyon hashes with ragu's width-5 Pasta Poseidon in fourteen places, all in `crates/tachyon/src/digest/poseidon.rs`.
- Five P1 rows (R1-R4, R6) are exposed on both axes. In each, the attacker prepares both sides of a collision and sets a raw field element in the final permutation call.
  - A collision in the note commitment or the payment key lets a user spend a note twice.
  - A collision between openings of different value, or between a pad or nullifier and a note commitment, mints value.
  - A collision in an evidence tree node forges a bucket, which mints value or hides a spend.
- R8 joins P1 when the payment protocol lets a sender pick rcm and psi.
- The fee descriptor digest (R14) mints value through a collision between two prepared max fee notes. Like the action digest (R7), it offers only black-box search, and both are P2.
- The fee blind (R13) lets a compromised author device redirect the fee change note. The owner's loss stays inside the signed maximum fee, and the row is P3.
- Orchard keeps its binding jobs on Sinsemilla, whose collision resistance reduces to discrete log.
- Ragu asks less of Poseidon. Its Fiat-Shamir transcript absorbs only commitment points, and it hashes no headers. **Superseded for `ragu-mock-adopt`.** The branch's in-step challenges absorb raw field elements as well as commitments (see [the Pending section](#pending-ragu-mock-adopt-f09bb21c)). On `main` the in-step challenges are BLAKE2b, so they are not Poseidon uses today.
- Poseidon for cm and pk is a deliberate choice. It buys binding that survives a quantum computer, while the rest of the stack still rests on discrete log.
- No public attack reaches full rounds on either axis. HashSmash's executed collisions stop at 5 of 56 partial rounds on Orchard's width-3 instance. No public program targets ragu's width-5 instance.

**Update (2026-10-26).**
- Since v2 the code has gained no Poseidon function and lost none. #234 changed the layout of all fourteen. Thirteen of the fourteen are now a single permutation call, so every free input of those hashes sits in the final call.
- R5 (anchor folds) now has a free predecessor word in the final call, and v2's "none in the final call" no longer holds. A concrete inflation route through SpendableInit is traced end to end in R5. It needs no collision and no publisher. R5 is rated P1, and v2's rubric is amended to say why (see Triage and R5). R5 is also marked as the cheapest inflation route. The disposition is raised to "decide with R1".
- R1's inflation variant and R2 gain a third free raw word. OutputBind witnesses a whole note, so `pk` is a raw word on the output side, and `rcm`, `pk` and `psi` all sit in the only call with `v` and the tag fixed. That meets the v2 condition for a second round skip (three free words, two fixed). The working degree for those two variants is 5^62. The double-spend variant and R4 keep two free words (the NoteSeed side derives `pk`) and stay at 5^63. **Superseded.** An earlier line of this revision counted two free words for R1 and R2 and kept 5^63.
- R11 (the untagged node) is superseded. #234 tags the node. R15 (new) records the latent case that replaces it, a tag with no length term.
- R13 and R14 keep their classes. Their step names, citations and the author and custody story are refreshed.
- The `ragu-mock-adopt` branch adds no Poseidon function and changes no layout. It adds an in-circuit copy of each hash and a mock Poseidon transcript for step challenges. That transcript is the one new requirement on Poseidon. Section "Pending" classifies it as R16 (P3, no attack path found).
- Net effect against v2. The P1 rows are now six (R1, R2, R3, R4, R5, R6), plus R8 under a sender-chosen opening, and the algebraic handle is stronger on R1 (inflation), R2 and R5. No attack reaches full rounds, so the likelihood stays low across the table.

## Threat model

Findings are ordered by harm.

1. Soundness. Inflation (value from nothing) and double spends.
2. Manipulation by a party the note owner did not consent to, such as a note's sender, an untrusted prover or a compromised author device.
3. Privacy and other property questions.

An authorized party acting within a signed bound follows the design. Under #233 the transaction author holds the max fee note's opening and may choose any fee up to the signed maximum. Custody signs with airgapped keys after deriving cv_maxfee from the opening itself.

Each risk is rated on two independent axes of exposure.

- **Generic search.** If the attacker prepares both sides of the equality a forgery needs, black-box search is a birthday search, about 2^127 for one 255-bit output word. If someone else fixed one side, black-box search costs about 2^254.
- **Algebraic handle.** If the attacker sets a raw field element that enters the final permutation call, the output is a one-variable polynomial in that element. Root finding on such polynomials is the method behind the HashSmash write-ups and the CICO bounties (constrained input, constrained output). In that model a collision and a fixed-target preimage cost about the same.
  - Skipping the first round gives degree 5^63. A second skipped round, as in the HashSmash write-ups, gives 5^62.
  - By the construction of Bariant et al., a second skip at width 5 needs at least three free words, with at most two fixed words (the capacity among them). This is an inference (see [Open questions](#open-questions)).
  - A free word that enters only an earlier call raises the degree to 5^127 or more.
  - No non-generic attack is known when every input is a curve point or a hash output.
  - **Update.** After #234 only `evidence_tree_leaf` has more than one call. For the other thirteen functions every input word sits in the one and only call. The "earlier call" case applies to the leaf alone (its first four words).

Privacy needs other properties (pseudorandomness and hiding), which R10 covers.

## The instance

Every Tachyon hash runs ragu's Poseidon sponge over the Pallas base field. `crates/tachyon/src/digest/poseidon.rs:28-31` and `44-70` evaluate the in-circuit sponge natively through ragu's wireless emulator, so native and in-circuit digests use the same code. (v2 cited `:20-29`, the pre-#234 location.) On `ragu-mock-adopt` the in-circuit side is separate code. Each hash has a `*_circuit` twin that runs on the caller's driver (see [Pending](#pending-ragu-mock-adopt-f09bb21c)).

| parameter | value | source |
|---|---|---|
| field | Pallas base field, p = 0x4000…224698fc094cf91b992d30ed00000001 | `ragu:crates/ragu_pasta/src/poseidon_fp.rs:1-3` |
| width, rate, capacity | 5, 4, 1 | `ragu:crates/ragu_pasta/src/poseidon_fp.rs:12-13` |
| rounds | 4 full, 56 partial (S-box on lane 0 only), 4 full | `ragu:crates/ragu_pasta/src/poseidon_fp.rs:14-15`, `ragu:crates/ragu_primitives/src/poseidon.rs:407-429` |
| S-box | x^5 | `ragu:crates/ragu_pasta/src/poseidon_fp.rs:16` |
| constants | hard-coded. A doc comment credits the Hades/Poseidon reference implementation, through the `daira/pasta-hadeshash` fork | `ragu:crates/ragu_pasta/src/poseidon_fp.rs:5-8` |

The sponge state starts at zero in all five lanes (`ragu:crates/ragu_primitives/src/poseidon.rs:112-124`). Absorbed values are buffered. When a fifth value arrives, the buffered four are added into lanes 0 to 3 and the state is permuted (`poseidon.rs:211-233`). A squeeze adds any buffered values, permutes once, and returns lane 0 first (`poseidon.rs:168-203`, `319-321`). Lane 4 is the capacity and never receives input.

**Update.** After #234 Tachyon does not start any hash from `Sponge::new`. `tagged_sponge` builds a state with the rate at zero and lane 4 holding the domain tag, then calls `Sponge::resume` (`ragu:crates/ragu_primitives/src/poseidon.rs:282`) over `SpongeState::from_elements` (`:310`) and absorbs the data (`crates/tachyon/src/digest/poseidon.rs:52-68`). The first absorb leaves squeeze mode and keeps the state. The capacity constant is a circuit constant (`Element::constant`), so it costs no gate. The first permutation input of a function with at most four data words is therefore (w0, w1, w2, w3, tag), with unused words zero.

The sponge has no padding and no length encoding. Its doc comment says so (`ragu:crates/ragu_primitives/src/poseidon.rs:81-85`).

<!-- prose-check:off -->

> absorbing a trailing zero looks identical to absorbing nothing: feeding it `[x]` and `[x, 0]` produces the same output.

<!-- prose-check:on -->

Each Tachyon function absorbs a fixed number of elements. **Superseded.** Thirteen of the fourteen absorbed a 16-byte domain tag first and `evidence_tree_node` absorbed four children and no tag. After #234 none absorbs a tag. All fourteen place the 16-byte domain, read as a little-endian integer below 2^128, in the capacity (`digest/poseidon.rs:49`). The fourteen tags are distinct and nonzero (each begins with `Tachyon-`). The capacity carries no length term (see [What #234 changed](#what-234-changed)).

The round counts follow the Poseidon paper's formulas (ePrint 2019/458, section 5.5). For the Pallas prime, x^5 and 128-bit security, the interpolation bound needs R_F + R_P ≥ 58. The cheapest choice is R_F = 6 and R_P = 52, at width 3 and at width 5. The designers' margin adds two full rounds and 7.5% more partial rounds, which gives 8 and 56. Ragu's instance has exactly that, as Orchard's does. The round-skipping technique of Bariant, Bouvier, Leurent and Perrin (ToSC 2022) removes two full rounds, and the two extra full rounds cover it. The paper's Table 2 lists 60 partial rounds at width 5. That is 56 rounded up to a multiple of the width, and the reference generator mentions this rounding (`code/generate_parameters_grain.sage:4` in `daira/pasta-hadeshash`).

The constants match the output of that generator at `daira/pasta-hadeshash` revision `5959f26`, run at width 5. The local ragu tree records the invocation and checks in the output (`ragu-local:qa/params/reference/PROVENANCE.md:8-15`). The MDS matrix is the first Cauchy candidate the generator's Grain stream yields (`PROVENANCE.md:17-19`). Neither ragu tree has a known-answer test of the width-5 permutation. The local tree tests the construction against halo2's width-3 vectors. **Update.** `main` still has no width-5 test of any kind in `digest/poseidon.rs`. `ragu-mock-adopt` adds one, which compares its sponge with the pinned ragu permutation (`pending:digest/poseidon.rs:613-736`). Both sides read the same round constants and MDS table, so it checks the layout and not the parameters.

Orchard's Poseidon is a different instance. It is P128Pow5T3 (width 3, rate 2, 8 full and 56 partial rounds, x^5) used in `ConstantLength<2>` mode, which sets the initial capacity to 2^65. Results against one instance do not carry over to the other as collisions. Techniques carry over.

## Inventory

The fourteen functions live in `crates/tachyon/src/digest/poseidon.rs`. The first table below is the layout at `6cdaebcc`. It gives the words each permutation call adds to lanes 0 to 3, the capacity (the domain tag, called T), the steps that compute the function, and what ties the output to public data. P1 and P2 are the first and second permutation calls of one sponge. A zero is a lane the hash leaves at zero. Step paths are relative to `crates/tachyon/src/stamp/proof/`. A line number after a function name is its definition in `digest/poseidon.rs`.

**Update.** Inventory at `6cdaebcc`.

| function | domain (capacity T) | permutation calls | computed in | output pinned by |
|---|---|---|---|---|
| `note_commitment` (:120) | `Tachyon-CmDerive` | P1 (rcm, pk, v, psi) | OutputBind (`output.rs:80`), NoteSeed (`delegation.rs:148`), FeeFuse (`stamp.rs:607`), FeeSeed (`stamp.rs:705`) | the published tachygram for an output or a fee change note. Membership in a stamp's tachygram set for a spend |
| `pad_tachygram` (:133) | `Tachyon-CmOutPad` | P1 (rcm, pk, v, psi) | OutputBind (`output.rs:81`) | the published tachygram |
| `payment_key` (:112) | `Tachyon-PkDerive` | P1 (ak.x, ak.y, nk, 0) | NoteSeed (`delegation.rs:142`), SpendAction (`stamp.rs:202-205`) | the note commitment, and the action signature over rk |
| `nf_master` (:147) | `Tachyon-NfMaster` | P1 (psi, nk, 0, 0) | NoteSeed (`delegation.rs:147`) | nothing public |
| `nullifier_group` (:185) | `Tachyon-NfDerive` | P1 (mk, w, 0, 0), four words squeezed | NullifierDerive (`delegation.rs:231`), SpendBind (`spend.rs:123-124`) | the published nullifier pair |
| `alpha_spend` (:159) | `Tachyon-Spend` | P1 (theta, cm, 0, 0) | SpendAction (`stamp.rs:210`) | the published rk and its signature |
| `alpha_output` (:171) | `Tachyon-Output` | P1 (theta, cm, 0, 0) | OutputAction (`stamp.rs:127`) | the published rk and its signature |
| `action_digest` (:104) | `Tachyon-ActionDg` | P1 (cv.x, cv.y, rk.x, rk.y) | OutputAction (`stamp.rs:130`), SpendAction (`stamp.rs:213`), the verifier (`bundle/mod.rs:843-848` through `action.rs:40`, `176`, `227`) | the verifier's rebuild of the action set from published actions |
| `fee_blind` (:83) | `Tachyon-FeeBlind` | P1 (pk, psi, rcm, 0) | FeeFuse (`stamp.rs:588`), FeeSeed (`stamp.rs:686`), the signer (`note.rs:84-85` through `bundle/mod.rs:467-471`, `510`, `582-585`) | the signed cv_maxfee, as its blind |
| `fee_digest` (:93) | `Tachyon-FeeDg` | P1 (cv_maxfee.x, cv_maxfee.y, fee, 0) | FeeFuse (`stamp.rs:603`), FeeSeed (`stamp.rs:701`), the verifier (`fee.rs:31-40` through `bundle/mod.rs:846`) | the verifier's rebuild of the action set from published fee descriptors |
| `anchor_next_stamp` (:223) | `Tachyon-AnchorSt` | P1 (prev, epoch, tgs_lo, tgs_hi) | SpendableInit (`spendable.rs:100-102`), AnchorSpanSeed (`pool.rs:198-200`), SummarySeed (`summary.rs:78-80`), SummaryAdvance (`summary.rs:119-121`), QrStampIntakeSeed (`qr.rs:191-193`) | consensus membership of the spend's anchor |
| `anchor_next_epoch` (:281) | `Tachyon-AnchorEp` | P1 (prev, epoch, 0, 0) | QrBucketSeal (`qr.rs:625-628`, `633-635`), the genesis anchor (`primitives/anchor.rs:12`) | consensus membership of the spend's anchor |
| `evidence_tree_leaf` (:237) | `Tachyon-QrBucket` | P1 (epoch, anchor_start, anchor_next, disc), P2 (depth, bits, c_lo, c_hi) | EvidenceTreeLeafPair (`evidence.rs:172`, `181`), EvidenceTreeOpen (`evidence.rs:518-530`) | nothing public. Leaves hash proven bucket headers |
| `evidence_tree_node` (:270) | `Tachyon-EvidNode` | P1 (c1, c2, c3, c4) | EvidenceTreeFuse (`evidence.rs:331`), EvidenceTreeCap (`:385`), EvidenceTreeDescend (`:453`) | nothing public |

Two alpha tags and the fee digest tag are zero padded to 16 bytes (`book/src/domain-separators.md`). The tables above and below list the native call sites. The wallet-side code reaches the same functions through `Note::commitment` (`note.rs:104`), `Note::fee_blind` (`note.rs:84`), `ProofAuthorizingKey::derive_payment_key` (`keys/proof.rs:42`), `NullifierKey::derive_note_private` (`keys/note.rs:40`), `NoteMasterKey::derive_nullifier` and `derive_window` (`keys/master.rs:38-80`), `ActionEntropy::randomizer` (`entropy.rs:126-130`), `ActionDigest::new` (`primitives/action_digest.rs:45`) and `Anchor::next_stamp` and `next_epoch` (`primitives/anchor.rs:43-72`).

### Property each use needs, and what an adversary gains

**Update.** This table is new. Each row names the property the use needs and what an adversary gains when it fails. "Collision resistance" means the attacker prepares both sides. "Second preimage" means one side is fixed by someone else. The risk column points to the section below. Steps with no Poseidon call are listed after the table.

| function | property needed | adversary gains if it fails | risk |
|---|---|---|---|
| `note_commitment` | collision resistance (two openings of one cm), second-preimage resistance (reopening a note someone else made), and hiding of the opening | spends one note twice under different psi, or draws more value than an output subtracted (inflation), or reopens a received note under the sender's pk (theft) | R1, R8 |
| `pad_tachygram` | collision resistance against `note_commitment` outputs, and unlinkability to cm | a pad that equals some note's cm mints that note with no output step behind it. A linkable pad reveals the output count | R2, R10 |
| `payment_key` | collision resistance (two nk, one pk), second-preimage resistance (sender reopens the recipient's pk), preimage resistance for nk | the owner spends a note under two master keys. A sender takes a note it paid. Anyone who holds a pk could recover its nk | R3, R8 |
| `nf_master` | PRF keyed by nk, and preimage resistance so mk reveals neither psi nor nk | linkage of a note's nullifiers to the note, and a delegate who recovers nk. No soundness effect (determinism is all balance needs) | R10 |
| `nullifier_group` | PRF keyed by mk over consecutive epochs (the weak-PRF property covers random inputs only), preimage resistance for the four published words, and collision resistance against `note_commitment` outputs | a sync service predicts or links a note's nullifiers (privacy). A nullifier equal to some cm mints that note. A nullifier collision between two notes blocks one spend (availability) | R10, R4 |
| `alpha_spend` | second-preimage resistance with theta free, and pseudorandomness | an untrusted prover moves a signed spend authorization to another note of the same key and value. Predictable alpha links rk to ak | R9, R10 |
| `alpha_output` | second-preimage resistance with theta free, and pseudorandomness | an untrusted prover diverts an outgoing payment to a recipient it picks | R9, R10 |
| `action_digest` | collision resistance between the proven (cv, rk) and the published (cv', rk') | a bundle publishes a value commitment the proof never covered, and the binding signature balances against it (inflation) | R7 |
| `fee_blind` | second-preimage and collision resistance (it binds the fee change note's owner into the signed cv_maxfee), and hiding so cv_maxfee hides maxfee | a compromised author device redirects the fee change. A weak blind reveals maxfee | R13, R10 |
| `fee_digest` | collision resistance between the proven (cv_maxfee, fee) and the published pair | a stamp proves a large max fee note against a small signed reservation, and the difference is minted | R14 |
| `anchor_next_stamp` | second-preimage resistance of accepted anchors, and collision resistance when a publisher controls placement | an invented creation set mints a note. An exclusion path over invented sets hides a published nullifier (double spend) | R5 |
| `anchor_next_epoch` | second-preimage resistance of accepted entry anchors, and collision resistance against `anchor_next_stamp` outputs across the two domains (`book/src/anchor.md:33`) | the same as the stamp fold, through a bucket sealed over invented stamps | R5 |
| `evidence_tree_leaf` | collision and second-preimage resistance (the leaf binds a bucket's header, profile and contents) | a forged bucket proves a published nullifier absent (double spend) or an invented cm present (inflation) | R6 |
| `evidence_tree_node` | second-preimage resistance with three free siblings, and collision resistance inside an attacker-built tree | the same as the leaf, through a forged descent | R6 |

Steps that call no Poseidon function: NullifierFuse, SpendableLift, QrSpendableInit, StampMerge, StampLift, ActionMerge, ActionLift, AnchorSpanFuse, QrSummaryIntake, QrEmptyIntakeSeed, QrIntakeMerge, QrIntakeSplit, QrSideDescend, QrUnspentInit, UnspentFuse, UnspentLift, UnspentBind, EvidenceTreePairFuse. On `main` every step that derives a Schwartz-Zippel challenge uses the mock's BLAKE2b hook (`ragu:src/mock/ctx.rs:33-52`), so none of them is a Poseidon use today.

<details>
<summary>Superseded v2 inventory table (layout at <code>b9e583ff</code>, before #234 and the #233 renames)</summary>

The permutation calls, the step names and the line numbers in this table no longer hold. P1, P2 and P3 were the first, second and third permutation calls, and D was the domain tag absorbed as a data word.

| function | permutation calls | computed in | output pinned by |
|---|---|---|---|
| `note_commitment` (:113) | P1 (D, rcm, pk, v), P2 (psi) | OutputBind (`output.rs:80`), NoteSeed (`delegation.rs:148`), FeeStamp (`stamp.rs:453`) | the published tachygram for an output or a fee change note. Membership in a stamp's tachygram set for a spend |
| `pad_tachygram` (:132) | P1 (D, rcm, pk, v), P2 (psi) | OutputBind (`output.rs:81`) | the published tachygram |
| `payment_key` (:100) | P1 (D, ak.x, ak.y, nk) | NoteSeed (`delegation.rs:142`), SpendStamp (`stamp.rs:177-180`) | the note commitment, and the action signature over rk |
| `nf_master` (:152) | P1 (D, psi, nk) | NoteSeed (`delegation.rs:147`) | nothing public |
| `nullifier_group` (:206) | P1 (D, mk, w), four words squeezed | NullifierDerive (`delegation.rs:231`), SpendBind (`spend.rs:123-124`) | the published nullifier pair |
| `alpha_spend` (:168) | P1 (D, theta, cm) | SpendStamp (`stamp.rs:185`) | the published rk and its signature |
| `alpha_output` (:184) | P1 (D, theta, cm) | OutputStamp (`stamp.rs:102`) | the published rk and its signature |
| `action_digest` (:86) | P1 (D, cv.x, cv.y, rk.x), P2 (rk.y) | OutputStamp (`stamp.rs:105`), SpendStamp (`stamp.rs:188`), the verifier (`crates/tachyon/src/bundle/mod.rs:940-941`) | the verifier's rebuild of the action set from published actions |
| `fee_blind` (:54) | P1 (D, pk, psi, rcm) | FeeStamp (`stamp.rs:438`), the signer (`crates/tachyon/src/fee.rs:24`) | the signed cv_maxfee, as its blind |
| `fee_digest` (:73) | P1 (D, cv_maxfee.x, cv_maxfee.y, fee) | FeeStamp (`stamp.rs:449`), the verifier (`crates/tachyon/src/fee.rs:137`) | the verifier's rebuild of the action set from published fee descriptors |
| `anchor_next_stamp` (:255) | P1 (D, prev, epoch, tgs_lo), P2 (tgs_hi) | SpendableInit (`spendable.rs:101`), AnchorSpanSeed (`pool.rs:199`), SummarySeed and SummaryAdvance (`summary.rs:79`, `120`), QrStampIntakeSeed (`qr.rs:192`) | consensus membership of the spend's anchor |
| `anchor_next_epoch` (:316) | P1 (D, prev, epoch) | QrBucketSeal (`qr.rs:627`, `634`), the genesis anchor (`crates/tachyon/src/primitives/anchor.rs:12`) | consensus membership of the spend's anchor |
| `evidence_tree_leaf` (:274) | P1 (D, epoch, anchor_start, anchor_next), P2 (disc, depth, bits, c_lo), P3 (c_hi) | EvidenceTreeLeafPair (`evidence.rs:174`, `183`), EvidenceTreeOpen (`evidence.rs:522`) | nothing public. Leaves hash proven bucket headers |
| `evidence_tree_node` (:305) | P1 (c1, c2, c3, c4), no tag | EvidenceTreeFuse (`evidence.rs:333`), EvidenceTreeCap (`:387`), EvidenceTreeDescend (`:455`) | nothing public |

</details>

The pairs (tgs_lo, tgs_hi) and (c_lo, c_hi) are the two 16-byte halves of a Vesta point's compressed encoding (`digest/poseidon.rs:190-212`, v2 cited `:222-244`).

**Superseded.** v2 wrote: "The untagged node overlaps every 3-word and 4-word tagged function (R11). The doc comments at `crates/tachyon/src/keys/mod.rs:49` and `book/src/keys.md:96` show pk absorbing only ak.x. The code absorbs both coordinates." The node is tagged since #234, so the overlap is gone (see R11). #234 also corrected both doc comments. They now read `Poseidon_domain(ak_x, ak_y, nk)` (`keys/mod.rs:49`, `book/src/keys.md:42`, `96-98`).

## Triage

A risk's priority combines its harm with its exposure on the two axes. Harm follows the threat model. No public attack on either axis reaches full rounds (see [State of cryptanalysis](#state-of-cryptanalysis)). The priorities rank exposure, and today's likelihood is low across the whole table.

- **P1.** Soundness harm, exposed on both axes. These need a decision before the circuits are fixed. **Update (rubric amended).** A row also counts as P1 when it gives any user unbounded, repeatable inflation or double spending through an algebraic handle alone, with no collision and no special position. R5 is that case. The amendment leaves R3 and R8 as they were. R3 is a collision (the owner prepares both nullifier keys), so both of its axes are exposed. R8's fixed-note case is bounded to one note and needs a sender, so it stays P2.
- **P2.** Soundness harm exposed on one axis, theft by a non-consenting party, or the assurance gap behind the P1 rows. These need tracking.
- **P3.** Privacy dependencies, latent overlaps, and redirection inside a signed bound. These are accepted and documented.

| | risk | harm | generic search | algebraic handle | attacker | priority | disposition |
|---|---|---|---|---|---|---|---|
| R1 | two openings of one note commitment | double spend, inflation | birthday | inflation variant, output side: rcm, pk and psi in the only call (5^62). Double spend: rcm and psi (5^63). v2: psi in the final call | any user | P1 | Decide whether the note commitment's binding stays on Poseidon collision resistance |
| R2 | a pad equal to a note commitment | inflation | birthday | rcm, pk and psi on the pad side (5^62, against a fixed NoteSeed cm). v2: psi in the final call | any user | P1 | Settle with R1 |
| R3 | two nullifier keys for one payment key | double spend | birthday | nk in the only call | the note's owner | P1 | Decide the payment key construction together with R1 |
| R4 | a nullifier equal to a note commitment | inflation | birthday across two families | rcm and psi on the commitment side (v2: psi) | any user | P1 | Settle with R1 |
| R6 | evidence tree openings | inflation, double spend | birthday in the attacker's own tree | three sibling words in a node (5^62) | any prover | P1 | Decide with R1 whether tree nodes stay on Poseidon collision resistance |
| R8 | a sender reopens a note it sent | theft, double spend | birthday when the sender picks the opening, otherwise fixed target | rcm' and psi', or nk', in the only call (v2: psi' or nk') | the note's sender | P1 when the payment protocol lets the sender pick rcm and psi, otherwise P2 | Settle with R1 and R3. State the payment protocol's rule |
| R5 | anchor folds | inflation, double spend | birthday for a publisher who controls placement, otherwise fixed target | the predecessor anchor in the only call, a free word at SpendableInit (v2: none in the final call, **superseded**) | any user, or a publisher | P1 (v2: P2), by the amended rubric. See R5 | Decide with R1. **The cheapest inflation route.** It needs no collision and no special position (v2: Accept) |
| R7 | action digests | inflation | birthday | none | any bundle author | P2 | Track |
| R9 | action randomizers | theft of an outgoing payment | fixed target | theta in the only call | an untrusted prover | P2 | Accept. Document the swap and the diversion |
| R14 | fee descriptor digests | inflation | birthday across two max fee notes | none | a bundle author | P2 | Track with R7 |
| R12 | no width-5 known-answer test or public cryptanalysis | assurance | n/a | n/a | n/a | P2 | Add a known-answer test. Seek width-5 cryptanalysis if the P1 rows stay on Poseidon. **Update.** #234 put the layout under no test on `main`, and `ragu-mock-adopt` adds a layout cross-check that shares the parameter table |
| R10 | privacy dependencies | privacy | n/a | n/a | an observer or a delegate | P3 | Accept. Document the PRF and hiding requirements |
| R11 | untagged tree node overlap | none today | n/a | n/a | n/a | P3 | **Superseded.** #234 tags the node (`Tachyon-EvidNode`), and the overlap no longer exists. The row is kept for the record. v2 disposition: Accept. Tag the node if node values ever leave the evidence steps |
| R13 | a compromised author device redirects the fee change note | redirection of the change, inside the signed maximum fee | birthday before custody signs, fixed target after | psi and rcm in the only call | a compromised author device | P3 | Accept. The signed maximum bounds the loss |
| R15 | a capacity that holds the tag and no length term | none today | n/a | n/a | n/a | P3 | Accept. Pin each tag to its arity with a test if a tag is ever reused. Replaces R11 as the latent no-padding case |
| R16 (pending) | Poseidon Fiat-Shamir challenges of `ragu-mock-adopt` (ten sites, three absorb a raw scalar) | a false identity accepted in an exclusion proof or an anchor span, if the transcript were broken | n/a | none found. The raw scalar is fixed by a second condition that no polynomial in the block reaches | any prover | P3, pending | Track. Redo with the real ragu transcript. See [Pending](#pending-ragu-mock-adopt-f09bb21c) |

## Risk areas

Code paths below are relative to `crates/tachyon/src/`. Paths starting with `book/` or `crates/` are relative to the repository root.

### R1. Two openings of one note commitment

A collision `note_commitment(rcm, pk, v, psi) = note_commitment(rcm', pk', v', psi')` gives one cm two openings. The step chain accepts either opening.

1. OutputBind witnesses the whole note as raw field elements and commits cv to −v (`stamp/proof/output.rs:55`, `72-90`).
2. NoteSeed witnesses (value, psi, rcm, pak) and derives pk, mk and cm (`stamp/proof/delegation.rs:125-150`). Its doc says "A seed can invent a note, so `cm` closes downstream" (`delegation.rs:112-113`).
3. SpendableInit and QrSpendableInit check only that cm is a root of a creation set (`stamp/proof/spendable.rs:90-93`, `181-184`).
4. SpendBind checks that the NoteSeed cm equals the lineage cm (`stamp/proof/spend.rs:106-109`). It derives the nullifier pair from mk (`spend.rs:123-124`) and commits cv to the NoteSeed value (`spend.rs:140`).

No other step sees the opening. NoteNullifiers carries (cm, epoch_start, nf_commit, epoch_end) (`delegation.rs:86-100`). The exclusion segments are note-blind (`stamp/proof/pool.rs:48-50`).

Openings with psi ≠ psi' have different master keys and different nullifier sequences, and the note can be spent once under each. Openings with v' > v let the spend draw more value than the output subtracted. The attacker picks rcm, pk and psi freely on the output side, and rcm, v and psi on the spend side. The book records the dependency at `book/src/proof-tree.md:354` (v2: `:342`), where cm is tied to the note "by `Poseidon` collision-resistance".

#233 adds a third creation path. FeeFuse computes the fee change note's commitment from the max fee note's opening and puts it in the tachygram set (`stamp/proof/stamp.rs:607`, `618-623`). FeeSeed does the same for a zero-action bundle (`stamp.rs:705`, `716-721`). The change note is spent like any other note, and R1 applies to it unchanged. A zero-value note is valid (`book/src/notes.md:16`), so the change note can carry value zero.

**Update (#234).** `note_commitment` is now one permutation call over (rcm, pk, v, psi) with the tag in the capacity (`digest/poseidon.rs:120-122`). v2 had psi alone in a second call. The free words now depend on the side of the collision.
- **Output side.** OutputBind (`output.rs:55`, `72-83`), FeeFuse (`stamp.rs:579-583`) and FeeSeed (`stamp.rs:677-681`) witness a whole `Note`, and nothing derives or checks pk. A bundle author controls that opening, so rcm, pk and psi are three free raw words in the only call, with v (range checked) and the tag fixed. That meets the v2 condition for a second round skip (at least three free words, at most two fixed). The inflation variant fixes a spendable NoteSeed opening with a large v' (its cm is the target) and solves the output side at a small v by root finding at degree about 5^62. This corrects a first pass of this revision, which counted two free words and treated pk as a hash output. That holds only for the NoteSeed side.
- **NoteSeed side.** NoteSeed derives pk from pak (`delegation.rs:141-148`), so rcm and psi are the two free words and pk and v are fixed. The double-spend variant needs both openings spendable, so both sides are NoteSeed sides, and the degree stays 5^63.
- **Basis.** The three-word condition is an inference in v2. The independent replica derives it from the linear-algebra argument that a second skip needs at least (t + 1) / 2 free lanes (two at width 3, three at width 5). I did not re-derive it and treat it as supporting evidence, not a proof.

### R2. A pad equal to a note commitment

`pad_tachygram` absorbs the same words as `note_commitment` under a different tag (`digest/poseidon.rs:120-135`, v2: `:113-140`). OutputAction puts both into the stamp's tachygram set (`stamp/proof/stamp.rs:149-154`, v2: OutputStamp at `:124-129`). The accumulator treats all tachygrams alike (`primitives/tachygram.rs:14-16`). The bundle verifier checks the tachygram count and the set commitment (`bundle/mod.rs:737-758`, `840-841`, v2: `:828-848`).

If `pad_tachygram(rcm, pk, v, psi)` equals `note_commitment(rcm', pk', v', psi')`, SpendableInit accepts the second opening as a created note. No output step ever subtracted v'. Both sides have free words. The pad is OutputBind's opening (`output.rs:81`), so rcm, pk and psi are three free raw words in its only call (see R1). The note side must be spendable, so it comes from NoteSeed and serves as the fixed target. The degree for the pad side is about 5^62, where v2's shifted-difference construction gave 5^63. The test `pad_differs_from_commitment` (`crates/tachyon/tests/integration/proof.rs:1888-1893`, v2: `:1876-1883`) compares one opening under both tags. FeeFuse and FeeSeed publish no pad (`stamp.rs:618-623`, `716-721`).

### R3. Two nullifier keys for one payment key

NoteSeed derives pk from its own pak (`delegation.rs:142`). SpendAction (v2: SpendStamp) checks a separately witnessed pak against the header's pk (`stamp/proof/stamp.rs:202-205`, v2: `:177-180`). Its doc says "`pk = payment_key(ak, nk)` is the only thing tying `ak` to the note" (`stamp.rs:170`, v2: `:145`).

A collision `payment_key(ak, nk1) = payment_key(ak, nk2)` gives one note two master keys (`delegation.rs:147`). The owner spends it once under each. nk is one free word of one permutation call, and ak can stay fixed. The call is (ak.x, ak.y, nk, 0) with the tag in the capacity (`digest/poseidon.rs:112-114`). #234 did not change the number of free words. Transfer proofs never constrain how nk is derived (`book/src/keys.md:105`).

### R4. A nullifier equal to a note commitment

A spend's nullifier pair enters the stamp's tachygram set (`stamp.rs:231-236`, v2: `:204-209`). If one of those nullifiers equals `note_commitment` of an opening the attacker knows, SpendableInit accepts that commitment as created (`spendable.rs:90-93`).

The attacker controls both families.
- **Nullifiers.** A source note's nullifiers come from `nf_master` and `nullifier_group` over witnesses the attacker picks (`delegation.rs:125-148`, `spend.rs:123-124`). The source note need not exist before the search.
- **Commitments.** A candidate commitment comes from NoteSeed, where pk derives from the attacker's pak (`delegation.rs:142`) and rcm and psi are free.

A cross-match between the two families is a birthday search. Fixing one nullifier and solving for psi is root finding in the commitment's final permutation call. The attacker then creates the source note and spends the invented one. After #234 the commitment call is its only call, and rcm is a second free word beside psi. The nullifier side is (mk, w, 0, 0) with mk a hash output and w an epoch index, so it has no free raw word.

### R5. Anchor folds

These steps fold anchors from free inputs:
- SpendableInit (`spendable.rs:100-102`)
- AnchorSpanSeed (`pool.rs:198-200`)
- SummarySeed (`stamp/proof/summary.rs:78-80`) and SummaryAdvance (`summary.rs:119-121`)
- QrStampIntakeSeed (`stamp/proof/qr.rs:191-193`)
- QrBucketSeal's `anchor_final_prev` (`qr.rs:625-628`)

**Superseded.** v2 wrote: "FeeStamp takes its anchor as a free witness, and StampMerge requires it to equal the anchor of the stamp it joins (`book/src/fee.md:189-190`). It folds nothing." The sentence names a step and a book line that no longer exist. FeeSeed takes its anchor as a free witness (`stamp/proof/stamp.rs:661`, `724`) and FeeFuse threads it from the left `Actions` (`stamp.rs:644`). StampMerge and ActionMerge require equal anchors (`stamp.rs:272-275`, `357-360`). None of the fee steps folds an anchor.

A forged lineage has to end on an anchor consensus accepted.
- **A fixed anchor.** Against an anchor already accepted, the first fold that lands on it is a second preimage.
- **An adaptive publisher.** An attacker who controls where a legitimate stamp lands can prepare that stamp and a forged fold together. The legitimate side's set commitment is sampled, and the forged side's predecessor is a free word. A cross-match is a birthday search.

In both cases the free predecessor enters the first of two permutation calls (`digest/poseidon.rs:255-264`). The final call has no algebraic handle. **Superseded.** Both sentences held for `anchor_next_stamp` at `b9e583ff`. #234 makes it one call over (prev, epoch, tgs_lo, tgs_hi) with the tag in the capacity (`digest/poseidon.rs:223-226`). The predecessor is then a free raw word in the only call. The other three words are an epoch index (range limited) and the two limbs of a sampled commitment point. The forger fixes the epoch and a forged creation set, so the equation is one polynomial in the predecessor, and root finding applies. v2's claim also missed `anchor_next_epoch`, which was one call at `b9e583ff` as well. QrBucketSeal's `anchor_final_prev` is a free word in that call (`digest/poseidon.rs:281-283`, `qr.rs:625-628`). So v2 was already inexact for the boundary fold.

The result is a handle on both folds. Against an accepted anchor the attacker still faces a fixed target (about 2^254 for black-box search, and about the same cost as the other single-word rows for root finding, which v2 estimates near 2^162 at 64 rounds ignoring memory). For an adaptive publisher the generic axis is a birthday search, so by v2's rule the row is exposed on both axes. This revision rates R5 as P1 for both variants (see "Route and rating" below). The code's statement that a later fold reaches the accepted chain "only by producing a Poseidon collision" (`qr.rs:599`, and `book/src/proof-tree.md:235`) holds in general. StampLift's "collides with `anchor_start` or a member" (`stamp.rs:428-429`, v2: `:317`) means equality with a published anchor.

An invented creation set mints a note. An exclusion path over invented sets hides a published nullifier and allows a double spend.

**Route and rating (update).** An independent replica traced a concrete inflation route. I checked each link against the code, and every link holds on `main`.
1. SpendableInit witnesses `(anchor_prev, creation_set, creation_epoch)` and emits `anchor = anchor_prev.next_stamp(creation_epoch, creation_commit)` (`spendable.rs:79`, `83-104`). Nothing else touches `anchor_prev`. The book states that it "is a free witness, so the anchor binds only downstream" and that "a chain node's preimage fixes the real predecessor" (`book/src/proof-tree.md:26`, `157`, `327-328`). That is a second-preimage dependency, and the fold is now one call with the predecessor alone in lane 0.
2. The only check on the creation set is that it vanishes at cm (`spendable.rs:90-93`). The attacker commits a creation set that holds the cm of an invented NoteSeed note (NoteSeed can invent a note, `delegation.rs:112-113`).
3. The attacker picks any accepted end-of-block anchor A and an epoch e, and solves `anchor_next_stamp(x, e, lo, hi) = A` for x, where (lo, hi) are the limbs of the forged set's commitment. That is one free word against three fixed words and the tag, a root of a polynomial of degree about 5^63.
4. SpendBind threads the spendable's anchor to the spend header and derives the nullifier pair at epoch e from mk (`spend.rs:103-124`). SpendAction puts that anchor on the `Actions` header (`stamp.rs:199-238`). A SpendableInit lineage spends in its creation epoch (`spendable.rs:199-202`), so it needs no lift.
5. Consensus checks the published anchor for chain membership, and the duplicate-tachygram window (`book/src/tachygrams.md:55-62`). The invented note's nullifiers were never published, so that window passes, and A is accepted. I found no step and no documented consensus rule that checks a spendable's anchor against the position of its creation stamp. The replica lists the same question as open for consensus rules outside the crate, and so do I (Open questions).

So the route is real end to end on `main`. The pending branch carries it unchanged (`pending:spendable.rs:121-132`).

The other free-predecessor seeds do not give the same route as far as I traced. SummarySeed and QrStampIntakeSeed put `anchor_prev` on their headers, and the QR and unspent steps compare it with the lineage (`pool.rs:397-400`, `spendable.rs:164-171`, `236-247`). AnchorSpanSeed's start is tied to the lifted stamp's anchor at StampLift (`stamp.rs:456-460`). I did not enumerate every step composition. QrBucketSeal's free `anchor_final_prev` lets a bucket start at a mid-epoch anchor. Its start is then pinned by the same equalities, and I found no harm there, on the replica's reading and on mine.

Rating. **R5 is P1.** The route needs no collision and no publisher, and the target is an accepted anchor chosen by consensus. Black-box search against a fixed target costs about 2^254, so by v2's original two-axis rule a fixed anchor exposes the algebraic axis only. Applied literally, that rule gives P2 (the class of R8's fixed-note case and R9). The independent replica rates the row P1 unconditionally. I checked the consistency argument against v2's other rows. R3 is not a fixed-target case. Its attack is a collision between two nullifier keys the owner chooses, so both axes are exposed, and v2 was consistent. The literal rule would still leave the row with the largest payoff at P2. The payoff is unbounded and repeatable inflation by any user, with no collision and no special position. That exceeds R9 and R8's fixed-note case, which are bounded to one note or one payment and need a narrower attacker. So the Triage rubric is amended. A row is P1 when it gives any user unbounded, repeatable inflation or double spending through an algebraic handle alone. R3 stays P1 and R8 and R9 stay P2. R5 is also the cheapest inflation route in this document, since it needs one root-finding problem against a public anchor. The disposition is "decide with R1".

### R6. Evidence tree openings

EvidenceTreeLeafPair hashes the headers of proven buckets (`stamp/proof/evidence.rs:172-189`, v2: `:174-191`). EvidenceTreeDescend accepts any four children that hash to the threaded node and selects one of them (`evidence.rs:450-462`, v2: `:451-463`). EvidenceTreeOpen requires the selected value to equal the leaf digest of the witnessed profile and contents (`evidence.rs:518-530`, v2: `:520-532`).

A forged descent needs a selected child the attacker can open. The attacker builds a false leaf and the path above it first, which fixes the selected child. The three sibling words stay free. With only the selected child and the capacity fixed, a line through the siblings can skip two rounds, for degree 5^62. This is unchanged after #234, which only moves the zero capacity to the tag `Tachyon-EvidNode`. By the v2 inference R6 is now the one row that meets the three-free-word condition.
- **The attacker's own tree.** Anyone can build a tree over genuine buckets, and "the tree claims nothing about which buckets it holds" (`evidence.rs:40-41`). The attacker prepares both sides of the node equality. A cross-match is a birthday search, and solving for the siblings is root finding in a single permutation call.
- **Another party's tree.** The node is a fixed target.

A second route goes through a leaf. Two leaves in one tree share the discriminant, a free witness (`qr.rs:129`, `604`) that joins require equal (`evidence.rs:167-170`, v2: `:169-172`). It enters the second of the leaf's three permutation calls, and each value gives one candidate pair. **Superseded** as to the position. After #234 the leaf has two calls and the discriminant is the fourth word of the first (`digest/poseidon.rs:247-259`). The two calls are P1 (epoch, anchor_start, anchor_next, disc) and P2 (depth, bits, c_lo, c_hi). The discriminant still enters only an earlier call, so the v2 conclusion holds. The degree in the discriminant is 5^127 or more, and each value still gives one candidate pair.

A forged bucket proves a published nullifier absent (a double spend) or an invented cm present (inflation). QrSpendableInit ignores the bucket's profile (`spendable.rs:153`).

### R7. Action digests

The verifier rebuilds the action set from digests of the published actions (`bundle/mod.rs:843-851`, `stamp/mod.rs:1182-1190`, v2: `bundle/mod.rs:940-941`, `stamp/mod.rs:1040-1053`). The action digest is the only link between the proof and the published (cv, rk).

A collision between a proven pair and a published pair (cv', rk') lets a bundle publish a value commitment the proof never covered. The binding signature then balances against cv'. To sign, the attacker needs the opening of cv' and the discrete log of rk' (`bundle/mod.rs:527-590`, v2: `:548-570`). Every input on both sides is a curve point the attacker samples through rcv and theta. No non-generic attack on such inputs is known. The attacker prepares both sides, so black-box search is a birthday search. **Update.** `action_digest` is one call over (cv.x, cv.y, rk.x, rk.y) after #234 (`digest/poseidon.rs:104-106`). The class is unchanged (no free raw word). The second permutation that v2 counted as extra margin against non-generic attacks is gone.

#233's fee digests join the same accumulator (`primitives/action_digest.rs:7-11`). The verifier requires 2N + K tachygrams for N actions and K fee descriptors, one per covered bundle (`bundle/mod.rs:742`, v2: `:833`, and `book/src/fee.md:128-134`). Swapping one action for one fee descriptor changes that count. A forgery across the two kinds needs two collisions that swap in opposite directions.

### R8. Targeted variants of R1 and R3

A sender knows the opening of every note it creates. The two cases differ in when that opening is fixed.
- **A prepared payment.** A sender who picks rcm and psi can search both openings before delivery, for `note_commitment(rcm, pk_recipient, v, psi) = note_commitment(rcm', pk_sender, v, psi')`. The recipient gets a spendable note, and the sender holds a second opening. This is R1's collision with one payment key fixed. Whether the sender picks rcm and psi depends on the payment protocol (`note.rs:17-18`).
- **A fixed note.** Reopening a note whose opening was fixed independently is a second preimage. It targets either the cm under the sender's pk (rcm' and psi' free) or the recipient's pk under the sender's ak' (nk' free).

Both are theft. The recipient can still spend the note under the original keys, so each also produces a double spend.

Under #233 the transaction author holds the max fee note's opening, and the fee change note goes to the max fee note's own pk (`crates/tachyon/src/stamp/mod.rs:430-433`, where v2 cited `fee.rs:39-50`, which no longer holds that code). Reopening the change note is the owner's R1, not a sender attack. **Update.** After #234 the rcm and psi of the commitment are two free words in the only call (see R1).

### R9. Action randomizers

The signer derives alpha from theta and cm and signs the sighash (`bundle/mod.rs:535-547`, v2: `:548-570`). The sighash covers each action's cv and rk (through `Bundle::commitment`, `bundle/mod.rs:234-242`, v2: `:489-500`). In the circuit theta is a free witness (`stamp.rs:113`, `186`, v2: `:87-88`, `160-166`), but the signed rk fixes alpha. The alpha hashes are one call over (theta, cm, 0, 0) with the tag in the capacity (`digest/poseidon.rs:159-173`), and theta is the one free word, as in v2.

Moving the authorization to a different note cm' needs a theta' with alpha(theta', cm') equal to the signed alpha. That is a fixed-target preimage with one free word in the only permutation call. The signed cv fixes the value.
- **Spend.** The action consumes a different note of the same key and value.
- **Output.** The action pays a same-value note to a recipient the prover picks, because the sighash covers neither cm nor the tachygrams. A prover that picks itself steals the payment.

Balance holds in both cases.

### R10. Privacy dependencies

Nullifier derivation carries no balance risk of its own. Balance needs a note's nullifiers to be a function of the note, which R1 and R3 provide. In the exclusion argument, a note's nullifiers are kept distinct by the epoch index in the encoding (m + (i+1)X)^3 − 2 (`collections/indexed_multiset.rs:8-17`, `54-69`). Their distinctness doesn't depend on Poseidon. Collisions among nullifiers break availability only.

- **One master key, two epochs.** Equal nullifiers at adjacent epochs make the spend's pair a duplicate, and `ProofStamp::read` rejects duplicate tachygrams (`stamp/mod.rs:323-331`, v2: `:312-322`).
- **Two notes, one nullifier.** One spend blocks the other. Picking a victim's nullifier needs the victim's master key.

Privacy rests on properties beyond collision and preimage resistance.
- **Nullifiers.** `nf_master` must be a PRF keyed by nk and `nullifier_group` a PRF keyed by mk. The inputs are sequential epochs, and the weak-PRF property Orchard relies on covers random inputs only. A delegate sees all four squeezed words of a group. Recovering mk from them is a CICO problem with one free word and four constrained outputs.
- **Commitment and pad.** cm and the pad come from one opening under two tags and are published together. They must hide the opening and look unrelated (`book/src/tachygrams.md:25`). Orchard's note commitment is perfectly hiding.
- **The spend/output split.** Pads must look like nullifiers, or the published set reveals which actions are outputs (`book/src/tachygrams.md:33`).
- **Action randomizers.** alpha must be pseudorandom for rk to hide ak (`entropy.rs:63-67`).
- **Max fee notes.** cv_maxfee hides maxfee only through its blind r, a Poseidon output (`book/src/fee.md:27-35`, v2: `:116-118`). Each max fee note needs a fresh, secret rcm, because the value is absent from the blind and reusing an opening reuses r (`fee.md:33-35`, v2: `:122-125`).

Tachyon leaves Faerie Gold to the payment protocol (`note.rs:3-6`, `nullifier/mod.rs:20-21`). Reusing psi for two notes to one pk needs no Poseidon event (`book/src/nullifiers.md:37`).

### R11. Untagged evidence tree node

**Superseded by #234.** The text below describes `b9e583ff` and is kept as the record. At `6cdaebcc` `evidence_tree_node` takes the tag `Tachyon-EvidNode` in its capacity (`digest/poseidon.rs:229`, `270-272`), so its first permutation input (c1, c2, c3, c4, T) never equals another function's first input. The overlap with the other thirteen functions is gone. Within one tag the sponge still has no padding, so inputs that differ by trailing zeros collide. No tag is used at two arities today (the capacity carries no length term). A new function that reuses a tag at another arity would reopen the case. A test that pins each tag to its arity does not exist. R15 records the remaining latent case.

v2 text. `evidence_tree_node` absorbs four children and no tag (`digest/poseidon.rs:297-307`), and the sponge has no padding. Every 3-word and 4-word tagged function therefore equals the node of its own words padded with zeros. For example, `payment_key(ak, nk)` equals the node of (D, ak.x, ak.y, nk), and #233's `fee_blind` and `fee_digest` equal the node of their four words. Tree roots stay inside the evidence steps, and no step accepts a node value in place of another function's output.

### R12. Width-5 assurance

Neither ragu tree has a known-answer test of the width-5 permutation (see [The instance](#the-instance)). No public cryptanalysis program targets the width-5 instance (see [State of cryptanalysis](#state-of-cryptanalysis)). HashSmash targets Orchard's width-3 instance, where a collision costs Orchard nothing. The P1 rows rest on the width-5 instance.

**Update.** #234 removed the second permutation from four hashes, and the P1 rows now rest on one call each (R6's node, R1, R2 and R4's commitment, R3's key). A single call with four data words is the standard fixed-length configuration, and the round numbers target it. The extra margin of the two-call versions is gone. `main` has no test of the tag layout. The review in `poseidon-capacity-review.md` asked for one (finding 2), and the landed code carries no such test and no length term. `ragu-mock-adopt` adds the cross-check described under [The instance](#the-instance).

The specification's note on Orchard's parameters cites the results of Keller and Rosemarin on active S-boxes in the middle rounds. It calls them "positive for security" for small widths, "such as t = 3 as used here" (§5.4.1.10, p. 88). No comparable note covers width 5.

### R13. The fee change note's owner

The signed cv_maxfee = [−maxfee]V + [r]R carries the fee change note's owner through its blind r = `fee_blind(pk, psi, rcm)` (`note.rs:84-88`, `book/src/fee.md:27-35`, v2: `fee.rs:24-29`, `fee.md:116-123`). The bundle commitment absorbs cv_maxfee (`bundle/mod.rs:234-242`, `464-473`, v2: `:249-259`). FeeFuse (v2: FeeStamp) recomputes r from a witnessed opening and derives the change note from the same (pk, psi, rcm) (`stamp/proof/stamp.rs:579-609`, v2: `:438-453`). FeeSeed does the same at `stamp.rs:677-707`. v2 quoted a doc comment saying cv_maxfee pins "through r the fee change note owner's" fields (`stamp.rs:369-371`). That comment is gone. `book/src/fee.md:33` now says "The blind binds the fee change note's owner fields into cv_maxfee". Discrete log binds maxfee, and `fee_blind` binds the owner.

Another opening (pk', psi', rcm') that yields the same r proves FeeFuse and receives the change. **Superseded.** v2 cited the test `fee_descriptor_mismatch_is_rejected` (`tests/integration/fee.rs:252-258`) as rejecting an opening that only swaps pk. That test does not exist at `6cdaebcc`, and no merged test substitutes a second opening.

The transaction author holds the opening and sets the fee. Custody keeps the signing keys airgapped and derives cv_maxfee from the opening before signing (`book/src/authorization.md:329`). The prover applies the fee with the same opening (`authorization.md:385-391`). The threat is a compromised author device facing honest custody. **Update.** `fee_blind` is one call over (pk, psi, rcm, 0) with the tag in the capacity (`digest/poseidon.rs:83-85`), so psi and rcm are the two free words, as in v2.
- **Before signing.** The device chooses psi and rcm for the opening custody derives from. It can prepare a second opening with the same blind, so both sides are its own, with psi and rcm free in the only call. Custody has to take pk from the user's own keys, or show it to the user. Otherwise the device can redirect the change without any collision.
- **After signing.** r is fixed, and a second opening is a fixed-target search.

The owner loses at most maxfee − fee, inside the signed maximum. The same device may already choose any fee up to maxfee (`book/src/fee.md:64`, v2: `:157`), which costs the owner the same amount. The difference is who receives it.

### R14. Fee descriptor digests

The verifier rebuilds each fee digest from the published cv_maxfee and fee (`crates/tachyon/src/fee.rs:31-40`, `bundle/mod.rs:843-848`, v2: `fee.rs:137-145`, `bundle/mod.rs:940-941`). FeeFuse (v2: FeeStamp) proves its fee digest from its own opening and fee (`stamp/proof/stamp.rs:603`, `611-616`, and FeeSeed at `:701`, `709-714` with fee zero). The fee digest is the only link between the proven fee change note and the published fee descriptor.
- **Two max fee notes.** A bundle author prepares two openings, a signed one with a small maxfee' and another with a large maxfee, whose fee digests collide at some fees f' and f. The bundle publishes (cv_maxfee', f'). FeeStamp proves the large opening, and the fee change note holds maxfee − f against a signed reservation of maxfee'. Both families are curve points with range-limited fees, and black-box search is a birthday search.
- **One max fee note, two fees.** A collision between fees f and f' under the signed cv_maxfee would let the published fee exceed the proven one. Both fees stay below 2^51 (FeeFuse bounds maxfee and maxfee − fee by MAX_MONEY, `stamp.rs:562-577`). A birthday search covers about 2^101 pairs per max fee note against a 255-bit output, and a root of the fee polynomial lands in range with probability about 2^-204.
- **After signing.** The signed cv_maxfee fixes one side. A second opening is then a fixed-target search over range-limited fees.

Custody's own derivation of cv_maxfee doesn't stop the two-note attack. Custody sees only the opening it signs, so a compromised author device can present the small opening and prove the large one.

### R15. A capacity that holds the tag and no length term

**Update (new row).** The independent replica raised this item, and I checked it against the code. `tagged_sponge` sets the capacity to the tag alone (`digest/poseidon.rs:49`). The ragu sponge has no padding and no length encoding (`ragu:crates/ragu_primitives/src/poseidon.rs:81-85`). Within one tag, inputs that differ by trailing zeros therefore give the same output. For example, a hash of (a, b) under a tag equals a hash of (a, b, 0) under the same tag. The reviewed construction (`poseidon-capacity-review.md`, `177ae3e7`) put the input count in the capacity as `tag + L * 2^128`, and #234 did not.

The case is latent. Each of the fourteen tags is used at one arity today, and the tags are distinct and nonzero. No two functions can agree by construction. A future function that reuses a tag at another arity, or a change in a function's arity, would reopen it. v2's R11 (the untagged node) was the instance of this case that existed before #234. R15 replaces R11 as the record of the no-padding property. No test pins a tag to its arity, and no test pins the layout on `main`.

## What ragu needs from Poseidon

Ragu's book states the assumption directly (`ragu:book/src/protocol/prelim/assumptions.md:26-31`).

> Ragu models Poseidon as a **random oracle** in the Fiat-Shamir transformation that makes the proof protocol non-interactive. This is a stronger assumption than collision resistance alone

Ragu calls Poseidon for one job, the Fiat-Shamir transcript.
- **Transcript.** The prover absorbs the coordinates of eight Pedersen commitments and squeezes eleven challenges (`ragu:crates/ragu_pcd/src/fuse/mod.rs:88-209`). Two circuits recompute the transcript in-circuit (`ragu:crates/ragu_pcd/src/internal/native/circuits/hashes_1.rs:234-273`, `hashes_2.rs:167-230`).
- **Headers.** PCD headers enter the instance polynomial k(Y) as raw field elements (`ragu:crates/ragu_pcd/src/header.rs:70-72`, `internal/native/stages/preamble.rs:130-139`). Ragu puts no Poseidon digest in a header.

Fiat-Shamir needs more than unpredictable challenges. A cheating prover wins by finding a transcript whose challenge satisfies a relation of its own choosing, such as a false polynomial identity that holds at that challenge (`crates/tachyon/src/relations/enforce.rs:74-77`). The random-oracle model covers this. Ragu's transcript absorbs only commitment points, which the prover can sample but can't choose. No non-generic attack on that setting is known. A collision alone gives the prover two transcripts that share one challenge, and that doesn't make a false relation hold.

Tachyon asks more of Poseidon than ragu does. Its P1 rows need collision resistance with raw field elements in the final permutation call, an algebraic handle ragu's transcript never offers. These requirements come from the Poseidon digests Tachyon places in its own headers.

Tachyon's steps also derive their own Schwartz-Zippel challenges (`crates/tachyon/src/relations/enforce.rs:74`, `116`, `crates/tachyon/src/stamp/proof/delegation.rs:236`, `crates/tachyon/src/stamp/proof/pool.rs:423`, `crates/tachyon/src/stamp/proof/qr.rs:488`, `804`). Ragu's step API derives each one as a Poseidon digest of a tag and the step's inputs, and a circuit in the parent proof re-derives it (`ragu-local:crates/ragu_pcd/src/internal/challenge.rs:21-35`). Tachyon's steps pass polynomial commitments as those inputs, so these challenges offer no algebraic handle either.

**Update (main at `6cdaebcc`).** The sites above are unchanged (`relations/enforce.rs:74`, `116`, `delegation.rs:236`, `pool.rs:423`, `qr.rs:488`, `804`). On `main` the call takes only commitment points (`ctx.derive_challenge(&[Eq])`) and the pinned mock hashes them with BLAKE2b, personalization `MkRagu_Challng_` (`ragu:src/mock/ctx.rs:33-52`). None of these challenges is a Poseidon use today. The `ragu-local` paragraph describes the real step API of a different ragu tree, and it is the target the mock stands in for. **Superseded for `ragu-mock-adopt`.** The last sentence ("these challenges offer no algebraic handle either") fails for two sites on the branch, which absorb raw field elements. No handle follows from that (see the next section, R16).

## Pending (ragu-mock-adopt f09bb21c)

Everything in this section is pending and applies to no code on `main`. The branch is 23 commits on top of `main` at `6cdaebcc` (that commit is the merge base). It rewrites every PCD step as a driver-generic circuit and patches ragu to a local tree (`Cargo.toml:231-237`, marked temporary). The patched tree is `ragu-mock` (`mock/closer-to-real` at `8a548a4a`). Paths in this section are `pending:` paths in `crates/tachyon/src/` unless they start with `ragu-mock:`. Nothing here was built or run. Test names are cited from the source.

The branch adds no Poseidon function and changes no tag, arity or layout (`pending:digest/poseidon.rs:1-7`, `45-85`). It adds two things. Each hash gets an in-circuit twin. The step challenges become a Poseidon transcript.

### Hashes as driver gadgets

Each row gives the in-circuit form of a function from the Inventory. The property needed and the harm on failure are the ones in the table above. A gadget that under-constrains the permutation would let a prover satisfy the step with a value other than the native hash. The in-circuit twin carries the same properties as the native function.

| function | circuit form | used in |
|---|---|---|
| `note_commitment` | `note_commitment_circuit` (`digest/poseidon.rs:223-242`) | OutputBind (`stamp/proof/output.rs:125`), NoteSeed (`delegation.rs:233-236`), FeeFuse (`stamp.rs:1031`), FeeSeed (`stamp.rs:1170`) |
| `pad_tachygram` | inline sponge, tag literal (`output.rs:126-140`) | OutputBind |
| `payment_key` | `payment_key_circuit` (`poseidon.rs:193-212`) | NoteSeed (`delegation.rs:218`), SpendAction (`stamp.rs:330`) |
| `nf_master` | inline sponge, tag literal (`delegation.rs:219-232`) | NoteSeed |
| `nullifier_group` | `nullifier_group_circuit` (`poseidon.rs:311-335`) | NullifierDerive, four groups per window (`delegation.rs:374-384`), SpendBind through `derive_nullifier` (`spend.rs:149-150`, `206-220`) |
| `alpha_spend` | inline sponge, tag literal (`stamp.rs:337-350`) | SpendAction |
| `alpha_output` | inline sponge, tag literal (`stamp.rs:193-206`) | OutputAction |
| `action_digest` | `action_digest_circuit` (`poseidon.rs:163-182`) | OutputAction (`stamp.rs:212`), SpendAction (`stamp.rs:357`) |
| `fee_blind` | `fee_blind_circuit` (`poseidon.rs:98-117`) | FeeFuse (`stamp.rs:1019`), FeeSeed (`stamp.rs:1162`) |
| `fee_digest` | `fee_digest_circuit` (`poseidon.rs:133-152`) | FeeFuse (`stamp.rs:1030`), FeeSeed (`stamp.rs:1169`) |
| `anchor_next_stamp` | `anchor_next_stamp_circuit` (`poseidon.rs:376-395`) behind `circuit::stamp_fold` (`stamp/proof/circuit.rs:207-243`) | SpendableInit (`spendable.rs:132`), AnchorSpanSeed (`pool.rs:262`), SummarySeed (`summary.rs:125`), SummaryAdvance (`summary.rs:223`), QrStampIntakeSeed (`qr.rs:321`) |
| `anchor_next_epoch` | two inline sponges, tag literals (`qr.rs:1129-1144`, `1151-1166`) | QrBucketSeal |
| `evidence_tree_leaf` | `evidence_tree_leaf_circuit` (`poseidon.rs:432-451`) behind `leaf` (`evidence.rs:68-89`) | EvidenceTreeLeafPair (`evidence.rs:245`, `254`), EvidenceTreeOpen (`evidence.rs:815`) |
| `evidence_tree_node` | `evidence_tree_node_circuit` (`poseidon.rs:466-485`) | EvidenceTreeFuse (`evidence.rs:458`), EvidenceTreeCap (`evidence.rs:541`), EvidenceTreeDescend (`evidence.rs:678`) |

What the branch changes about these uses.
- **Layout assurance.** Tests in `poseidon.rs` check that each circuit twin accepts the native value and rejects the value plus one (`:511-578`), that the four nullifier lanes are bound (`:581-611`), and that the sponge matches an independent copy of the permutation from ragu 0881656 at and past the absorb rate (`:613-736`). This partly answers the missing layout test in R12. The independent copy reads the same round constants and MDS table, so no test compares against outside vectors.
- **Five inline copies.** `pad_tachygram`, `nf_master`, `alpha_spend`, `alpha_output` and the two `anchor_next_epoch` sponges repeat the tag as a byte literal outside `digest/poseidon.rs`. Tag uniqueness then depends on the literals agreeing with the constants. A mismatch in a hash that no verifier recomputes (for example the pad) would define a different function in the circuit without failing any check. This is a P3 observation about maintenance and carries no known exploit.
- **Stamp fold preconditions.** `stamp_fold` rejects an identity commitment and the first host generator as the stamp set and bounds the epoch to `EPOCH_MAX` before it hashes (`circuit.rs:218-241`). This matches the range-limited epoch and sampled commitment limbs that R5 assumes.
- **Class.** No risk row changes class from this change alone. R1 to R14 keep their classes.

### Step challenges as a Poseidon transcript

`StepCtx::derive_challenge` is a mock extension that real ragu does not define (`ragu-mock:src/lib.rs:46-49`, `src/mock/ctx.rs:94-116`). The hook starts a zero-state sponge with `Sponge::new`, absorbs the constant `raguchal` (an 8-byte tag read as an integer, `ragu-mock:src/mock/hooks.rs:165`) as the first data word, absorbs every element the gadget writes, and squeezes one element (`hooks.rs:99-111`). The width is variable and the domain is data, not capacity. The mock states that real ragu uses a fixed-width recursive transcript and that outputs agree only when the absorbed sequences are identical (`ctx.rs:103-107`). The classification below therefore applies if real ragu adopts a Poseidon transcript of this shape, and it depends on an API that does not exist at the pinned revision.

Property needed. Random-oracle (Fiat-Shamir) soundness. The prover commits to polynomials, the challenge z is derived from the transcript, and the step checks an identity at z. A false identity must not hold at z for any transcript the prover can produce. If the property fails, the prover chooses an operand after z (see the table).

| site | words absorbed | identity checked at the challenge | raw field word absorbed | adversary gains if the property fails |
|---|---|---|---|---|
| `enforce_poly_product` (`relations/enforce.rs:86-93`) | six limbs (three commitments) | product(z) = multiplicand(z) * multiplier(z) | none | a merged set that is not the product of its inputs. A stamp then covers other actions or tachygrams than its parts (ActionMerge, StampMerge, FeeFuse, NullifierFuse, AnchorSpanFuse and the QR merges) |
| `enforce_poly_roots` (`enforce.rs:197`) | two limbs (the accumulator only) | accumulator(z) = product of (z − root) | none. The roots are not absorbed (`enforce.rs:181-185`), as on `main` | an action or tachygram set that does not commit to the proven roots (OutputAction, SpendAction, FeeFuse, FeeSeed) |
| `NullifierDerive` (`delegation.rs:368`) | two limbs (sequence) | sequence(z) = product of the derived window members | none | a nullifier window other than the derived one, which later binds a wrong tested value |
| constant-polynomial shim (`enforce.rs:162-172`) | two limbs and the scalar | shim(c) = scalar | **the scalar**, in the last lane of the only block (raguchal, lo, hi, scalar) | the shim commits to a non-constant polynomial and passes as the constant. The prover then picks the tested value or discriminant after the main challenge. Callers are QrSideDescend (`qr.rs:913-919`, scalar discriminant + depth), QrUnspentInit (`qr.rs:1449-1455`, scalar the tested value) and UnspentLift (`pool.rs:693-699`, scalar the tested value). An exclusion proof for a value other than the note's nullifier hides a published nullifier (double spend) |
| QrSideDescend, QrUnspentInit and UnspentLift main challenges (`qr.rs:921-927`, `1457`, `pool.rs:701-704`) | four to eight limbs, shim limbs included | the class, sequence and extension identities | none | the same prover choice of operand after z, if the shim relation fails first |
| AnchorSpanSeed singleton (`pool.rs:263-268`) | two limbs (members) and `anchor_end` | members(z) = z − anchor_end | **`anchor_end`**, a Poseidon fold of a free predecessor | a span whose members polynomial is not X − anchor_end. Extra members let StampLift or ActionLift move a stamp anchored off the published chain to `anchor_end`. Tests reject a wrong root, a scaled singleton and a quadratic (`tests/integration/proof.rs:409-422`) |

The shim tests are `qr_unspent_init_rejects_an_independent_or_nonconstant_value_shim` (`tests/integration/qr.rs:3021`), `qr_side_descend_rejects_an_independent_or_nonconstant_discriminant_shim` (`:3047`) and `unspent_lift_rejects_an_independent_or_nonconstant_value_shim` (`:3110`).

**Raw words in the block, and why they give no handle.** On `main` every challenge input is a commitment limb. On the branch the shim and singleton openings absorb a raw field word. The shim challenge is one permutation of (raguchal, lo, hi, s, 0). **Superseded.** An earlier pass of this revision called this a one-free-word CICO instance (R15, P2) and treated the equation P(c) = s as an attack on the shim. The independent replica argued that a non-constant shim still fixes the scalar before the main challenge. I checked that against the code, and it holds.
- **Shims.** The scalar is one circuit element. The shim opening takes it (`pending:relations/enforce.rs:162-172`), and the main identity takes the same element (`pending:qr.rs:1449-1462`, `pool.rs:693-715`, `qr.rs:913-938`). The main challenge is z = T(sequence limbs, shim limbs), so it does not depend on s directly. A forgery needs the main identity to hold at z for a value v' that the prover picks after z. For QrUnspentInit that means (N + e z)^3 = (v' + e z)^3, where N is the member the exported sequence claims, so v' is a function of z. The shim must then satisfy S(c') = v' at c' = T(limbs(S), v'). The only free inputs are S's coefficients, whose commitment fixes z, v' and c' together. The condition is a fixed point through a curve point encoding, and no polynomial in any word of the Poseidon block reaches it. Grinding costs about 2^255 per success. The word s sits in the block, but its value is fixed by a second condition outside the block. That is why the raw word is no handle.
- **AnchorSpanSeed singleton.** The opening checks M(z) = z − a with z = T(M limbs, a) (`pending:pool.rs:263-268`). An extra member b gives (z − a)(z − b − 1) = 0, so z = a or z = b + 1. Either is a fixed point of a hash of M's commitment, with b inside M. The cost is again about 2^255 per success, and `anchor_end` reaches the block only through the fold, which adds a second permutation.
- **Other sites.** Product, roots, NullifierDerive and the main challenges absorb commitment limbs only. The v2 conclusion (no algebraic handle) holds for them.

Classification (pending). **R16 (pending), P3.** The requirement on Poseidon is random-oracle (Fiat-Shamir) soundness at about ten sites. I found no attack path, and the harm if the oracle model failed is soundness (a false identity accepted in an exclusion proof or an anchor span). I rate it P3 and track it. The classification depends on an API that real ragu does not have, and it needs redoing with the real transcript. R16 replaces the R15 label that an earlier pass of this revision gave this item. R15 is now the capacity and length item.

Residual items on the mock transcript, none with a known exploit.
- All sites share the one tag `raguchal`, a zero capacity, and no site or length separation (`ragu-mock:src/mock/hooks.rs:99-111`).
- The sponge has no length term, so absorbing [lo, hi] and [lo, hi, 0] gives the same output. A roots challenge on a handle H and a constant-polynomial challenge on H with scalar zero are the same value. Both depend only on H's commitment, so neither site gains from the coincidence today.
- No width-5 known-answer test covers the constants (R12).

### Unchanged by the branch

- The ragu pin at `0881656` stays in `crates/tachyon/Cargo.toml:77-96`. Only the workspace patch points elsewhere.
- Poseidon parameters. The constants and the MDS matrix are read from the same ragu tables. The field type under the branch is `udon` (`Cargo.toml` dependency `zakura-udon`). The cross-check test above compares canonical bytes against the legacy field.
- The R5, R6, R7, R13 and R14 attack structures. They depend on the hash layout, which is identical.
- BLAKE2b digests and the cryptanalysis picture.

## Orchard

Orchard uses Poseidon for one job, the nullifier PRF. Its binding jobs use Sinsemilla, whose collision resistance reduces to discrete log. Section numbers refer to the Zcash protocol specification (v2026.7.0).

| job | Orchard | Tachyon |
|---|---|---|
| note commitment | SinsemillaCommit (§5.4.8.4) | `note_commitment` (R1, R2) |
| binding nk to the recipient | Commit^ivk, a Sinsemilla short commitment (§5.4.8.4) | `payment_key` (R3) |
| pool state | a Merkle tree over SinsemillaHash (§5.4.1.3) | the anchor chain over Pedersen set commitments (R5) |
| nullifier | PoseidonHash as a PRF keyed by nk (§5.4.2), added to cm inside a curve point (§4.16) | `nf_master` and `nullifier_group` (R10) |
| fee | the value balance under the binding signature | a signed max fee note, with `fee_blind` and `fee_digest` (R13, R14) |
| proof transcript | BLAKE2b (`orchard/src/circuit.rs:877`) | Poseidon |

Orchard's fee is the value balance, enforced by the binding signature (`book/src/fee.md:11-16`). It has no deferred fee and no fee change note.

The halo2 book says Sinsemilla's "only claimed security property" is "collision-resistance for fixed-length inputs". It says Sinsemilla "is not designed to be used where a random oracle, PRF, or preimage-resistant hash is required". As a commitment it is "computationally binding and perfectly hiding". Orchard's nullifier design notes put Balance on discrete log. Adding cm to the nullifier lets Faerie Gold resistance avoid collision resistance of the PRF.

The specification draws the conclusion (§5.4.1.10, p. 88).

> Also note that the use of Poseidon in Orchard is very conservative. [...] Given the weak assumption that the PoseidonHash sponge produces output that preserves sufficient entropy from the inputs nk and ρ, this nullifier construction would still be secure under a Decisional Diffie–Hellman assumption on the Pallas curve, even if the Poseidon-based PRF were distinguishable from an ideal PRF.

The fallback is conditional. It needs the sponge's output to keep enough entropy from nk and ρ.

Zooko's post of 2026-10-12 states the same position for Zcash users. It says the only property Zcash needs from Poseidon is the weak-PRF property.

Tachyon chose hash commitments for cm and pk on purpose.
- **Binding against a quantum computer.** "In contrast to Sapling/Orchard, the note commitment in Tachyon [...] is purely based on symmetric primitives" (`book/src/revisit.md:188-189`). ZIP 2005 (Proposed) says "the note commitment algorithms used by the Sapling and Orchard shielded protocols are not post-quantum binding". Its recovery path for Orchard derives rcm from a hash of the note.
- **No published ak.** A hash-based pk avoids handing ak to senders, which "exposes the user 'Harvest Now, Decrypt Later' risk" (`revisit.md:160-163`, `book/src/keys.md:107`).

The quantum benefit waits on other upgrades. Ragu's polynomial commitments, the value commitment cv and the spend-authorization signature all rest on discrete log. The book lists the proof system and the signature as future replacements (`revisit.md:2859-2865`, `2890-2899`). Today a discrete-log break hurts Tachyon and Orchard alike. A collision-only break of Poseidon hurts Tachyon through its P1 rows and leaves Orchard intact.

## State of cryptanalysis

Sources were read on 2026-10-16 and are not refreshed in this revision (2026-10-26). As of the read date, no public attack reaches full rounds of a recommended x^5 Poseidon instance over a 255-bit field.

- **HashSmash, Poseidon-Orchard track.**
  - **Targets.** Orchard's width-3 instance in `ConstantLength<2>` mode, keeping all 8 full rounds and the first r of the 56 partial rounds (`verifier/poseidon.py` and `pareto/target-profiles/` in `Layr-Labs/hash-smash-pareto`).
  - **Claims.** Submission branches hold collision claims for r = 1 to 5, at 2^24.9 to 2^34.7 target compressions. A claim for r = 7 was never run, and it rests on a premise its author calls "an assumption with no proof known to us". The repository lists no accepted round counts (`pareto/benchmark.json`).
  - **Method.** Each write-up restricts (nk, rho) to a line, skips two full rounds with the trick of Bariant, Bouvier, Leurent and Perrin, and finds collisions as roots of the odd part of a one-variable polynomial of degree 5^(r+6). Time grows about 2.5 bits per partial round.
- **Distance to full rounds.** The univariate root-finding cost formula of Grassi, Koschatko and Rechberger (ToSC 2025, eq. 11) puts the 2^128 line near 50 total rounds once two rounds are skipped. Orchard and ragu have 64. This document estimates the cost at 64 rounds near 2^162, ignoring memory.
- **Fit to Tachyon.** Root finding needs a free word in the final permutation call.
  - R3 varies nk alone, and R1 varies psi, which sits alone in the second permutation call. With one free word the method skips only the first full round (Bariant et al., conclusion). The full-round degree is then 5^63, against 5^62 for the HashSmash target. **Superseded for R1.** After #234 psi shares the only call with rcm (see R1). R3 is unchanged (nk is the one free word of (ak.x, ak.y, nk, 0)).
  - R1's inflation variant and R2 fix two different prefixes (two values, or two domain tags) and look for a root of the difference of the two polynomials in psi. Shifting psi on one side so that both sides enter the first S-box identically keeps the degree at 5^63. The HashSmash write-ups implement the single-polynomial form only. **Update.** The free words are now rcm, pk and psi on the output (or pad) side, with v and the tag fixed, and rcm and psi on the NoteSeed side. The tags are now capacity words that differ between the two sides, where v2 had them as data in lane 0. For the inflation variant and R2 the NoteSeed side is a fixed target. The attack is a fixed-target preimage on the three-word side at degree about 5^62, and the shifted-difference construction is not needed. The shift argument for two free words is unchanged in kind and still unverified for width 5.
  - R6's three free sibling words leave only the capacity and the selected child fixed. A line through them can skip two rounds, for degree 5^62.
  - R4, R8, R9 and R13 also have a free word in the final call. R5, R7 and R14 do not. **Superseded for R5.** `anchor_next_stamp` has the predecessor as a free word in its only call after #234, and `anchor_next_epoch` had it at `b9e583ff` as well (see R5). R7 and R14 still have none. For R5 the single-word bound applies (degree 5^63, near the single-word cost this document estimates at 2^162 or more, ignoring memory).
  - **Update, pending.** The shim and singleton challenges of `ragu-mock-adopt` put a raw word in a one-block transcript, and the word is fixed by a second condition outside the block (see R16). No root finding applies.
- **Ethereum Foundation Poseidon Cryptanalysis Initiative.**
  - **255-bit instances.** Its bounty instances over the BLS12-381 scalar field (width 3, x^5, R_F = 6) are solved for R_P = 8 and 9, and open for R_P = 11 and 16.
  - **KoalaBear.** A partial collision (3 words) on full-round Poseidon1 over KoalaBear at width 16 was claimed on 2026-04-06. The collision prize has been paused since 2026-08-01.
- **Chosen MDS matrices.** Midpoint Reset (ePrint 2026/1760) and Slipway (ePrint 2026/1579) break full-round KoalaBear instances at width 16 when the MDS matrix is chosen after the round constants. Ragu's matrix is the generator's first Cauchy candidate (see [The instance](#the-instance)).
- **Round-number analyses.** Grassi, Koschatko and Rechberger (ePrint 2025/954) conclude that "the security of POSEIDON/POSEIDON2 and NEPTUNE is not threatened by the attacks presented in this paper". For fields near 2^256 they find the best algebraic attacks use univariate roots or resultants. ePrint 2026/1905 improves resultant attacks on round-reduced Poseidon.
- **Khovratovich (ethresear.ch, 2026-09-23).** "ZK-friendly hash functions such as Tip5 and the Poseidon variants remain unbroken, but their cryptanalysis is still advancing at a notable pace. We cannot consider them mature yet."
- **Width 5.** No public program or paper found targets a width-5 Pasta instance.

## Open questions

- **Consensus rules outside the crate.** This document takes the anchor membership check, anchor recency and the two-epoch duplicate-tachygram rule from `book/src/tachygrams.md:55-62` (v2: `:56-62`) and `crates/tachyon/src/primitives/tachygram.rs:22-24`. R5 and R10 depend on them.
- **The zero guard at `crates/tachyon/src/stamp/proof/spend.rs:126`.** Its comment says a zero nullifier "would collide with the note's own cm tachygram". The reason doesn't follow from the current code.
- **Round skips at width 5.** The one-round skip for one free word, the shifted difference polynomial for two prefixes, and the two-round condition at width 5 (three free words, at most two fixed) are inferences from Bariant et al. None of the HashSmash write-ups covers these cases. **Update.** After #234 this question decides the degree of R1's inflation variant and R2 (three free words, so 5^62 if the condition holds) and whether R4, R1's double spend and R5 (one or two free words) stay at 5^63. The question carries more weight than in v2. The replica's argument (a second skip needs at least (t + 1) / 2 free lanes) supports the three-word condition at width 5, and it is a sketch, not a published result for this instance.
- **ePrint 2026/1792.** It reports nonlinear trails that reach "or even exceed the recommended number of internal rounds" for "several concrete instances". The instances weren't visible.
- **Update. R5 route.** The SpendableInit route is traced end to end on `main` (see R5). One question stays open, the same one the replica lists. No consensus rule outside the crate is known to check a spendable's anchor against the position of its creation stamp. A rule that did would close the route. The other seeds and QrBucketSeal (`qr.rs:594-602` on `main`) were traced by reading their equalities and not by enumerating step compositions.
- **Update. Tag and arity (R15).** #234 dropped the length term from the capacity. Nothing enforces one arity per tag, and no test pins the layout on `main`.
- **Update. Real ragu transcript (R16).** The pending classification assumes a Poseidon transcript of the mock's shape. Real ragu at the pinned revision has no such API.
- **Update. Not refreshed.** HashSmash and the other sources in the cryptanalysis section were not re-read after 2026-10-16.

## Sources

Code and documents are cited in place: Tachyon at `6cdaebcc` (`main`, with #233 as `eeddbb77` and #234 as `6cdaebcc` on `7acbdf59`), the `ragu-mock-adopt` branch at `f09bb21c`, ragu at `0881656`, the patched ragu tree `mock/closer-to-real` at `8a548a4a`, the local ragu tree, `poseidon-orchard-analysis.md`, `poseidon-capacity-domains.md`, `poseidon-capacity-review.md` and the independent replica `tachyon-poseidon-risk-replica.md` in this directory. Three points where this document and the replica first differed (the R5 route, the R1 and R2 free words, the pending transcript row) were settled against the code. R5 is rated P1 under an amended rubric. Citations marked "v2" were at `b9e583ff`. Version 1 of this document is `poseidon-tachyon-risk.md`.

- PR #233, dynamic fee mechanism. https://github.com/tachyon-zcash/tachyon/pull/233
- PR #234, Poseidon domain strings. https://github.com/tachyon-zcash/tachyon/pull/234
- Zooko Wilcox, Bluesky thread, 2026-10-12. https://bsky.app/profile/zooko2.bsky.social/post/3mxoce5ahyk2i
- HashSmash. https://www.yukon.org/hashsmash and https://github.com/Layr-Labs/hash-smash-pareto
- Zcash Protocol Specification. https://zips.z.cash/protocol/protocol.pdf
- ZIP 2005, Ironwood Quantum Recoverability. https://zips.z.cash/zip-2005
- halo2 book, Sinsemilla. https://zcash.github.io/halo2/design/gadgets/sinsemilla.html
- Orchard book, Nullifiers. https://zcash.github.io/orchard/design/nullifiers.html
- Grassi et al., Poseidon (ePrint 2019/458). https://eprint.iacr.org/2019/458
- `daira/pasta-hadeshash`. https://github.com/daira/pasta-hadeshash
- Bariant, Bouvier, Leurent and Perrin, ToSC 2022(3). https://tosc.iacr.org/index.php/ToSC/article/view/9850
- Grassi, Koschatko and Rechberger, ToSC 2025(2) (ePrint 2025/954). https://eprint.iacr.org/2025/954
- Midpoint Reset (ePrint 2026/1760). https://eprint.iacr.org/2026/1760
- Slipway (ePrint 2026/1579). https://eprint.iacr.org/2026/1579
- Resultant attack on round-reduced Poseidon (ePrint 2026/1905). https://eprint.iacr.org/2026/1905
- Nonlinear trails (ePrint 2026/1792). https://eprint.iacr.org/2026/1792
- Ethereum Foundation Poseidon Cryptanalysis Initiative. https://www.poseidon-initiative.info/
- Khovratovich, Post-Poseidon. https://ethresear.ch/t/post-poseidon-hash-function-variants-for-ethereum/26071
