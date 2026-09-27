# Tachyon Bundle / Aggregate Transaction Format

**Tracking:** [#104](https://github.com/tachyon-zcash/tachyon/issues/104)

**('Additive / Update' ZIP, Category 'Consensus')**

## I. Dependencies

* [Tachyon Shielded Protocol (#103)](https://github.com/tachyon-zcash/tachyon/issues/103) defines the Tachyon pool, action semantics, tachygrams, keys, and the statement the stamp proof attests to.
* [Tachyon Accumulator / Hash Chain (#105)](https://github.com/tachyon-zcash/tachyon/issues/105) defines the anchor (Poseidon hash-chain state) that `anchorTachyon` references, the consensus anchor-membership rule, and the epoch window with its duplicate-tachygram rule.
* [ZIP 225](https://zips.z.cash/zip-0225) is the v5 transaction-format precedent this format follows; the withdrawn [ZIP 230](https://zips.z.cash/zip-0230) is the v6 precedent.
* [ZIP 239](https://zips.z.cash/zip-0239) defines `wtxid = txid || auth_digest`, the identifier format carried by `tachyonAggregateId`.
* [ZIP 244](https://zips.z.cash/zip-0244) defines the `txid_digest` and `auth_digest` trees.
  ZIP 244 as extended for Tachyon ([Transaction digest contributions](zip-244.md#transaction-digest-contributions)) specifies the leaf algorithms and personalizations for this bundle's digest contributions; this ZIP specifies only their inputs, as ZIP 225 defers its digest algorithms to ZIP 244.

## II. Design Considerations

This ZIP is the Tachyon analogue of [ZIP 225](https://zips.z.cash/zip-0225): the wire format of the bundle that goes on-chain.[^bundle]

This draft adds the bundle to the existing transaction format as a new section, in the manner of ZIP 225's shielded fields.
It does not build on the extensible transaction-format proposal ([ZIP-248](https://github.com/zcash/zips/pull/1156)); see the open questions.

The [Tachyon Aggregator Protocol (#106)](https://github.com/tachyon-zcash/tachyon/issues/106) builds on this ZIP: it defines the aggregation lifecycle, the mempool and relay policy, and the autonome, aggregate, and adjunct transaction roles.
This ZIP defines the proof and pointer stamp forms and the adjunct bundle those roles build on; the draft body below otherwise speaks of the covering transaction without naming the roles.

[^bundle]: See [Bundle](../bundle.md) for the bundle lifecycle and state machine.


Open questions:

* **ZIP-248 migration.** If the extensible transaction format ([ZIP-248](https://github.com/zcash/zips/pull/1156)) lands, the bundle re-registers as a `(bundleType, bundleVariant)` TLV entry (see [the ZIP-248 entry](zip-248.md) and the registration draft in [tachyon-zcash/zips#4](https://github.com/tachyon-zcash/zips/pull/4)).
Under TLV framing, absence of the entry encodes "no bundle", making the `0x00` state byte redundant there.
* **Proof-size constant.** A fixed-size `proofTachyon` is the working assumption: its length is a constant of the Ragu proof system, not yet numerically frozen, so this draft names it symbolically as `PROOF_SIZE`.
A variable-size final compression (bulletproof-style) would replace the constant-length field with a dynamic one; whether the proof system settles on a fixed size is unresolved.
  The production proof encoding and parameters still need a fixed normative reference.
  The [proof-padding review comment](https://github.com/tachyon-zcash/tachyon/pull/157#discussion_r3583485122) identifies a separate canonicality issue in the current mock codec; fixing the proof size alone would not resolve it.
* **Zero-action coverage confirmation.** Consensus confirms that an adjunct bundle's reference identifies a proof-stamped transaction in the same block.
  For a bundle with no actions, it does not confirm that the referenced transaction absorbed the bundle's former stamp.
Two candidate rules:
  
  1. Validators holding mempool data locate a proof-stamped form matching the adjunct bundle's `txid`, identify its tachygram set, and confirm that set folded into the referenced aggregate.
  Multiple proof-stamped candidates may exist.
  Requires no changes to bundle format.
  Significantly, this check depends on ephemeral mempool state.
  2. A field is added to the bundle identifying the bundle's tachygram set at creation.
  The field contributes to `txid` and the sighash.
  A validator would confirm that the identified tachygram set is a subset of the referenced aggregate's tachygrams.
  The body field survives stripping and does not depend on mempool state.
  This would add a tachygram-set identifier to the effecting data.

* **Tachygram arity.** [#164](https://github.com/tachyon-zcash/tachyon/issues/164) proposes two tachygrams per action and considers removing `hStampActionsTachyon` in favor of total reconstruction.
  The current implementation emits two tachygrams for both spends and outputs and checks the count against the covered actions, but retains `hStampActionsTachyon`.
  These differences need to be reconciled; this draft does not adopt an arity rule or remove the indicator.
* **Memo payload structure.** This ZIP treats `vMemoTachyon` as opaque bytes and gives its contents no structure.
* **Count caps.** This draft gives `nActionsTachyon`, `nTachygrams`, and `nMemoTachyon` the compactSize maximum `0x02000000`.
  A tachygram multiset of size $n$ requires $n+1$ polynomial coefficients, so its commitment requires that many generators ([Multiset commitments](#multiset-commitments)).
  The implementation already rejects an empty tachygram vector and one exceeding this generator limit.
  At the proof system's current rank that generator count is $2^{13}$, so the commitment alone admits at most $8191$ tachygrams; the implementation's two-per-action check makes the count even, giving at most $8190$ tachygrams over at most $4095$ covered actions.
  Those bounds also reach the actions in each covered bundle, because those actions are included in the coverage.
  Which proof-system limits to state as explicit format-level caps remains undecided.

The digest leaf algorithms and personalizations live in [ZIP 244 as extended for Tachyon](zip-244.md#transaction-digest-contributions); see that page for their normative form.

This draft stages the ZIP body below inside the Tachyon mdBook, so two conventions differ from a standalone ZIP and normalize on migration to `tachyon-zcash/zips`.
The book reserves the top-level `#` heading for the page title, so the ZIP's own sections use `##` and `###` here and each promotes by one level (`#`, `##`) when the ZIP stands alone.
External ZIP and protocol references are written as full `https://zips.z.cash/` links for the book, where a standalone ZIP omits that prefix per the ZIP style guide.

## III. ZIP Draft

--------------------------------------------------------------------------------

```
ZIP: <to be assigned by ZIP Editors>
Title: Tachyon Bundle / Aggregate Transaction Format
Owners: <Tachyon team>
Status: Draft
Category: Consensus
Created: 2026-07-02
License: MIT
Discussions-To: <https://github.com/tachyon-zcash/tachyon/issues/104>
```

## Terminology

The key words "MUST", "MUST NOT", "SHOULD", "SHOULD NOT", "MAY", and "RECOMMENDED" in this document are to be interpreted as described in BCP 14 [^BCP14] when, and only when, they appear in all capitals.

The term "network upgrade" is to be interpreted as described in ZIP 200.[^zip-0200]
The terms "Testnet" and "Mainnet" are to be interpreted as described in § 3.12 ‘Mainnet and Testnet’.
The character § is used when referring to sections of the Zcash Protocol Specification.[^protocol]

`txid`, `auth_digest`, and the SIGHASH transaction hash are defined by ZIP 244 [^zip-0244]; `wtxid = txid || auth_digest`, the 64-byte identifier used for transaction announcement and relay, by ZIP 239 [^zip-0239].
Value commitments, spend authorization signatures, and binding signatures are existing constructions (§ 5.4.8.3 ‘Homomorphic Pedersen commitments (Sapling and Orchard)’, § 4.15 ‘Spend Authorization Signature (Sapling and Orchard)’, and § 4.14 ‘Balance and Binding Signature (Orchard)’, respectively, in their Orchard instantiations); this ZIP applies them to Tachyon as specified below rather than redefining them.

The following terms are defined by other Tachyon ZIPs and summarized here non-normatively:

Tachygram
:   The `byte[32]` encoding of a field element ($\mathbb{F}_p$) representing either a note nullifier or a note commitment.
    Consensus treats nullifiers and commitments identically (see [Tachyon Shielded Protocol](https://github.com/tachyon-zcash/zips/blob/37159f1bb23430ec07c5d731dece7f55d8bc90d3/zips/draft-tachyon-shielded-protocol.md)).

Anchor
:   A Poseidon hash-chain state referencing the *Tachyon pool* at a specific block.
    The chain advances at sub-block granularity, but consensus acknowledges only
    end-of-block states as anchors, as described in the Tachyon Shielded Protocol ZIP
    under [Tachygram accumulator](https://github.com/tachyon-zcash/zips/blob/37159f1bb23430ec07c5d731dece7f55d8bc90d3/zips/draft-tachyon-shielded-protocol.md#tachygram-accumulator)
    and [Per-stamp checks](https://github.com/tachyon-zcash/zips/blob/37159f1bb23430ec07c5d731dece7f55d8bc90d3/zips/draft-tachyon-shielded-protocol.md#per-stamp-checks).

Multiset commitment
:   As defined in [Multiset commitments](https://github.com/tachyon-zcash/zips/blob/37159f1bb23430ec07c5d731dece7f55d8bc90d3/zips/draft-tachyon-shielded-protocol.md#multiset-commitments)
    in the Tachyon Shielded Protocol ZIP. Its application to this format is
    described under [Multiset commitments](#multiset-commitments) below.

Stamp
:   The proof-bearing protocol object defined under
    [Stamp](https://github.com/tachyon-zcash/zips/blob/37159f1bb23430ec07c5d731dece7f55d8bc90d3/zips/draft-tachyon-shielded-protocol.md#stamp) in the Tachyon Shielded Protocol ZIP.
    This ZIP defines two wire forms for a bundle's final section: a proof stamp
    carrying that object, or a pointer stamp referring to a covering transaction.

The remaining terms are defined by this ZIP:

Bundle
:   The Tachyon section of a transaction: actions, a value balance, action signatures, a binding signature, and a state-dependent stamp.

Bundle state
:   The three-valued wire discriminator `tachyonBundleState` selecting no bundle, a proof stamp, or a pointer stamp.

Action
:   The triple $(\mathsf{cv}, \mathsf{rk}, \mathsf{sig})$: a value commitment, a randomized verification key, and a signature over the transaction sighash.
    An action effects a spend or an output; both forms share this encoding, and consensus applies the same rules to each.

Action digest
:   The Poseidon digest of an action's $(\mathsf{cv}, \mathsf{rk})$ pair.

Descriptor digest
:   The BLAKE2b-256 digest of a sequence of action descriptors (see [Action descriptor digests](#action-descriptor-digests)).

Proof stamp
:   A wire representation of a stamp, carrying a Ragu proof and supporting verification data: a digest of the covered actions, an anchor, and the stamp's tachygrams.
    The proof attests that every covered action satisfies the Tachyon action rules.

Pointer stamp
:   A wire form carrying `tachyonAggregateId`, the `wtxid` of a covering transaction, in place of a proof stamp.

Covering transaction
:   The proof-stamped transaction whose stamp covers a pointer-stamped transaction's actions, named by the pointer-stamped bundle's `tachyonAggregateId`.

## Abstract

This ZIP is a living draft and does not prescribe whether the Tachyon bundle is
deployed through ZIP 248's extensible transaction format[^zip-0248] or incorporated
directly into a new transaction format. Its encoding and integration details may
be revised as ZIP 248 and other related draft ZIPs evolve.

This ZIP specifies the consensus wire format of the Tachyon bundle: a three-state discriminator byte, a bundle body carrying actions, a value balance, and signatures, and a stamp carrying either a proof (with the public data needed to verify it) or a pointer to a covering transaction.
It defines the canonical field encodings and sequence orders, the action and descriptor digests, and the use of the shielded protocol's multiset commitments in bundle verification.
It further defines the bundle's transaction-digest inputs, the consensus rules scoped to a single bundle, and the block-scoped rules that validate a block's bundles together.
It defines the transaction representation of the
[*Tachyon pool*](https://github.com/tachyon-zcash/zips/blob/37159f1bb23430ec07c5d731dece7f55d8bc90d3/zips/draft-tachyon-shielded-protocol.md), just as ZIP 225 [^zip-0225]
defines the v5 transaction fields for the [Orchard shielded protocol](https://zips.z.cash/zip-0224).

## Motivation

To improve scalability, the [Tachyon shielded protocol](https://github.com/tachyon-zcash/zips/blob/37159f1bb23430ec07c5d731dece7f55d8bc90d3/zips/draft-tachyon-shielded-protocol.md) introduces support for [proof aggregation](https://github.com/tachyon-zcash/zips/blob/37159f1bb23430ec07c5d731dece7f55d8bc90d3/zips/draft-tachyon-aggregation-protocol.md): the [stamps](https://github.com/tachyon-zcash/zips/blob/37159f1bb23430ec07c5d731dece7f55d8bc90d3/zips/draft-tachyon-shielded-protocol.md#stamp) of many transactions merge into one covering stamp, and covered transactions appear in a block with their stamp stripped and replaced by a [pointer](#pointer-stamp).
The transaction format must therefore allow a stamp to be removed without changing the transaction's identity and without invalidating any signature.
This forces the effecting/authorizing split down into the wire layout: the bundle's contribution to the signed data is confined to the body and is identical across bundle states, while the strippable part is isolated in the stamp.

A single format serves every transaction role: one proof-stamped form whether the proof covers only the bundle's own actions or other transactions' (through aggregation) as well, and a covered transaction is the same body under a pointer stamp.
A pointer-stamped transaction retains the data needed for its signature and balance checks; proof coverage is checked using the covering transaction and the other bundles in the block.

## Requirements

* A transaction's `txid` contribution is invariant across stamping, merging, stripping, and re-stamping.
* Proof-stamped and pointer-stamped forms carry identical effecting data; only the stamp differs.
* Every field a validator needs for signature and balance verification is present in both states.
* Encodings are canonical: each parsed bundle has exactly one serialization.
* The proof field has a fixed size, so parsing requires no untrusted length.
* Bundles with no actions are representable, under both stamp forms.

## Non-requirements

This ZIP does not independently define:

* the multiset commitment construction, which is specified in the
  [Tachyon Shielded Protocol](https://github.com/tachyon-zcash/zips/blob/37159f1bb23430ec07c5d731dece7f55d8bc90d3/zips/draft-tachyon-shielded-protocol.md#multiset-commitments) ZIP;
* the proof statement, which is specified in the Tachyon Shielded Protocol ZIP
  under [Stamp](https://github.com/tachyon-zcash/zips/blob/37159f1bb23430ec07c5d731dece7f55d8bc90d3/zips/draft-tachyon-shielded-protocol.md#stamp) and
  [Proof tree](https://github.com/tachyon-zcash/zips/blob/37159f1bb23430ec07c5d731dece7f55d8bc90d3/zips/draft-tachyon-shielded-protocol.md#proof-tree);
* the tachygram accumulator, anchor semantics and validity rules, and cross-block
  duplicate-tachygram checks within the retained epoch window, which are specified
  in the Tachyon Shielded Protocol ZIP under
  [Tachygram accumulator](https://github.com/tachyon-zcash/zips/blob/37159f1bb23430ec07c5d731dece7f55d8bc90d3/zips/draft-tachyon-shielded-protocol.md#tachygram-accumulator),
  [Epochs](https://github.com/tachyon-zcash/zips/blob/37159f1bb23430ec07c5d731dece7f55d8bc90d3/zips/draft-tachyon-shielded-protocol.md#epochs), and
  [Per-stamp checks](https://github.com/tachyon-zcash/zips/blob/37159f1bb23430ec07c5d731dece7f55d8bc90d3/zips/draft-tachyon-shielded-protocol.md#per-stamp-checks);
* the transaction digest trees, the digest leaf algorithms, or the sighash algorithm, which are specified by ZIP 244 [^zip-0244] as extended for Tachyon ([Transaction digest contributions](zip-244.md#transaction-digest-contributions));
* the aggregation lifecycle, mempool, and relay policy, which will be specified in
  the [Tachyon Aggregation Protocol](https://github.com/tachyon-zcash/zips/blob/37159f1bb23430ec07c5d731dece7f55d8bc90d3/zips/draft-tachyon-aggregation-protocol.md) ZIP;
* the position of the bundle section within the transaction encoding, which is specified by the transaction format of the activating network upgrade.

## Specification

The specification proceeds from the wire layout of the bundle body to the rules over its fields, then to the digest constructions and multiset commitment inputs those rules use, then to the two stamp forms.
It closes with the canonical encodings of every field, the bundle's transaction-digest inputs, a consolidated summary of the bundle-scoped consensus rules, and the block-scoped rules that validate a block's bundles together.

### Placement and bundle states

The Tachyon bundle is a contiguous section of the transaction encoding, added by a Tachyon network upgrade.
The first byte of the section, `tachyonBundleState`, selects the bundle state:

| value         | state         | bundle contents                                       |
| ------------- | ------------- | ----------------------------------------------------- |
| `0b0000_0000` | non-tachyon   | no bundle                                             |
| `0b0000_0001` | proof stamp   | bundle with actions digest, anchor, tachygrams, proof |
| `0b0000_0010` | pointer stamp | bundle with covering transaction's wtxid              |
| `...`         | *reserved*    | *n/a*                                                 |

A parser MUST reject any other value of `tachyonBundleState`.
When `tachyonBundleState` is `0x00`, the Tachyon section consists of the discriminator byte alone.

The complete wire layout across the serialized states:

#### Bundle Flag

| Bytes                  | Name                   | Data Type                   | Description                          |
| ---------------------- | ---------------------- | --------------------------- | ------------------------------------ |
| 1                      | `tachyonBundleState`   | `uint8`                     | `0x00`, `0x01`, or `0x02`            |

#### Bundle body encoding

Present when `tachyonBundleState` is not `0x00`.

| Bytes                  | Name                   | Data Type                   | Description                          |
| ---------------------- | ---------------------- | --------------------------- | ------------------------------------ |
| 8                      | `valueBalanceTachyon`  | `int64`                     | Net value of Tachyon actions         |
| 1 or 3                 | `nActionsTachyon`      | `compactSize`               | Number of Tachyon actions, 0 to 4095 |
| 64 * `nActionsTachyon` | `vActionsTachyon`      | `byte[64][nActionsTachyon]` | Action descriptor per action         |
| 64 * `nActionsTachyon` | `vActionSigsTachyon`   | `byte[64][nActionsTachyon]` | Authorizing signature per action     |
| 64                     | `bindingSigTachyon`    | `byte[64]`                  | Binding signature for the bundle     |
| 1 or 3                 | `nMemoTachyon`         | `compactSize`               | Byte length of memo, 0 or more       |
| `nMemoTachyon`         | `vMemoTachyon`         | `byte[nMemoTachyon]`        | Opaque bytes                         |

#### Proof stamp encoding

Present when `tachyonBundleState` is `0x01`.

| Bytes                  | Name                   | Data Type                   | Description                          |
| ---------------------- | ---------------------- | --------------------------- | ------------------------------------ |
| 32                     | `hStampActionsTachyon` | `byte[32]`                  | Digest of covered action descriptors |
| 32                     | `anchorTachyon`        | `byte[32]`                  | Pool state anchor                    |
| 32                     | `cTachygrams`          | `byte[32]`                  | Multiset commitment to tachygrams    |
| 1 or 3                 | `nTachygrams`          | `compactSize`               | Number of tachygrams, 2 to 8190      |
| 32 * `nTachygrams`     | `vTachygrams`          | `byte[32][nTachygrams]`     | Tachygrams                           |
| `PROOF_SIZE`           | `proofTachyon`         | `byte[PROOF_SIZE]`          | Ragu proof                           |

#### Pointer stamp encoding

Present when `tachyonBundleState` is `0x02`.

| Bytes                  | Name                   | Data Type                   | Description                          |
| ---------------------- | ---------------------- | --------------------------- | ------------------------------------ |
| 64                     | `tachyonAggregateId`   | `byte[64]`                  | wtxid of a covering transaction      |

### Bundle body

When `tachyonBundleState` is not `0x00`, the body follows the discriminator byte, laid out as in the wire layout above.

`valueBalanceTachyon` is a two's-complement signed 64-bit integer in little-endian byte order.
`vActionsTachyon` is a sequence of `nActionsTachyon` action descriptors, each the 32-byte encoding of $\mathsf{cv}$ followed by the 32-byte encoding of $\mathsf{rk}$.
`vActionSigsTachyon` is a sequence of `nActionsTachyon` 64-byte signatures; the $i$-th signature authorizes the $i$-th descriptor.
Both sequences share the single count `nActionsTachyon`, so a count mismatch between descriptors and signatures is unrepresentable.
The descriptor sequence's order is the transaction author's choice.
The semantics of the actions themselves (what a spend or an output effects in the pool) are specified by the [Tachyon Shielded Protocol](https://github.com/tachyon-zcash/zips/blob/37159f1bb23430ec07c5d731dece7f55d8bc90d3/zips/draft-tachyon-shielded-protocol.md) ZIP.

`vMemoTachyon` is an opaque recipient-directed payload of `nMemoTachyon` bytes; `nMemoTachyon` of $0$ encodes an absent payload.
The memo contributes to `txid` and the sighash ([Transaction digest contributions](#transaction-digest-contributions)) rather than to `auth_digest`, so it is identical across bundle states.

### Value balance and the binding signature

`valueBalanceTachyon` is the bundle's net value, spends minus outputs. A positive
balance releases value from the *Tachyon pool*; a negative balance transfers value
into it.

Tachyon reuses Orchard's value commitments[^protocol-valuecommit] and binding-key
derivation and binding-signature construction,[^protocol-orchardbalance] applied
to the bundle's action value commitments and `valueBalanceTachyon`.
`bindingSigTachyon` MUST verify over the transaction sighash under the resulting
binding validating key $\mathsf{bvk}$, which is derived rather than serialized.

### Action signatures

Each action signature in `vActionSigsTachyon` MUST be a valid spend authorization signature (§ 4.15 ‘Spend Authorization Signature (Sapling and Orchard)’; RedPallas with the SpendAuth basepoint of § 5.4.7.1, for spends and outputs alike) over the transaction sighash under the corresponding action's $\mathsf{rk}$.
The sighash is a transaction-level digest, computed as specified by ZIP 244 [^zip-0244] as extended for Tachyon ([Transaction digest contributions](zip-244.md#transaction-digest-contributions)); all of a bundle's signatures sign the same sighash.

### Action digests

Each action has an action digest, a Poseidon hash of its $(\mathsf{cv}, \mathsf{rk})$ pair.
Let $(\mathsf{cv}_x, \mathsf{cv}_y)$ and $(\mathsf{rk}_x, \mathsf{rk}_y)$ be the affine Pallas coordinates of the action's decompressed $\mathsf{cv}$ and $\mathsf{rk}$.
Then

$$
  d = \mathrm{Poseidon}\bigl(
    \mathsf{dom},\ \mathsf{cv}_x,\ \mathsf{cv}_y,\ \mathsf{rk}_x,\ \mathsf{rk}_y
  \bigr)
$$

where $\mathsf{dom}$ is the Pallas base field element whose integer value is the little-endian interpretation of the 16-byte ASCII string `Tachyon-ActionDg`.
The Poseidon instance (width, rounds, round constants, and mode) is the instance fixed by the Ragu proof system.

If an action's $\mathsf{cv}$ or $\mathsf{rk}$ is the identity point, it has no affine coordinates, the digest is undefined, and the transaction is invalid.

### Action descriptor digests

An action's descriptor is its 64-byte encoding in `vActionsTachyon`: the 32-byte encoding of $\mathsf{cv}$ followed by the 32-byte encoding of $\mathsf{rk}$.
The descriptor digest of a sequence of actions is the BLAKE2b-256 hash, with personalization `Tachyon-Actions`, of the concatenation of their descriptors:

$$
  \mathsf{h} = \text{BLAKE2b-256}\bigl(
    \text{"Tachyon-Actions"},\ \mathsf{cv}_1 \| \mathsf{rk}_1 \| \cdots \| \mathsf{cv}_n \| \mathsf{rk}_n
  \bigr)
$$

The digest of the empty sequence is the hash of the empty string under the same personalization.

This construction is used for two distinct digests, over two distinct sequences:

* `hActionsTachyon`, an input to the effecting digest contribution ([ZIP 244 as extended for Tachyon](zip-244.md#transaction-digest-contributions)), is computed over the bundle's own actions in their `vActionsTachyon` wire order.
  It is not carried on the wire.
* `hStampActionsTachyon`, carried on the proof stamp ([Proof stamp](#proof-stamp)), is computed over every action a proof stamp covers, first sorted into ascending lexicographic order.
  Sorting makes it a function of the covered action multiset alone, independent of which transactions contributed it, or in what order a merge combined them.

### Multiset commitments

Multiset commitments MUST use the construction specified in the
[Tachyon Shielded Protocol](https://github.com/tachyon-zcash/zips/blob/37159f1bb23430ec07c5d731dece7f55d8bc90d3/zips/draft-tachyon-shielded-protocol.md#multiset-commitments) ZIP.

Each proof stamp binds two commitments: `cStampActionsTachyon`, over the action
digests of every action it covers, and `cTachygrams`, over its published tachygrams.
Validators reconstruct `cStampActionsTachyon` from the covered actions; it is not
serialized. The bundle carries `cTachygrams`, which validators MUST check against
the commitment reconstructed from `vTachygrams`, as specified under
[Block validity](#block-validity).

### Proof stamp

When `tachyonBundleState` is `0x01`, the proof stamp follows the body, laid out as in the wire layout above.

`hStampActionsTachyon` is the descriptor digest ([Action descriptor digests](#action-descriptor-digests)) over every action the stamp covers: the bundle's own actions together with the actions of every covered transaction.
How a block's actions are checked against it is specified in [Block validity](#block-validity).

`anchorTachyon` references the pool state the proof is valid against; its semantics
and the anchor-membership rule are specified in the Tachyon Shielded Protocol ZIP
under [Tachygram accumulator](https://github.com/tachyon-zcash/zips/blob/37159f1bb23430ec07c5d731dece7f55d8bc90d3/zips/draft-tachyon-shielded-protocol.md#tachygram-accumulator)
and [Per-stamp checks](https://github.com/tachyon-zcash/zips/blob/37159f1bb23430ec07c5d731dece7f55d8bc90d3/zips/draft-tachyon-shielded-protocol.md#per-stamp-checks).

`cTachygrams` is the multiset commitment ([Multiset commitments](#multiset-commitments)) over the tachygrams the stamp publishes.
It is carried rather than derived by the reader, so a validator MUST confirm it against `vTachygrams` ([Block validity](#block-validity)).

`vTachygrams` publishes the stamp's tachygram multiset for data availability.
Which tachygrams an action contributes is specified by the [Tachyon Shielded Protocol](https://github.com/tachyon-zcash/zips/blob/37159f1bb23430ec07c5d731dece7f55d8bc90d3/zips/draft-tachyon-shielded-protocol.md) ZIP; this ZIP imposes no relation between `nTachygrams` and `nActionsTachyon`, and a stamp covering actions that are not the bundle's own carries their tachygrams too.
The tachygrams within one proof stamp MUST be distinct; a transaction violating this rule is invalid.
Block-level distinctness is a block-validity rule of this ZIP
([Block validity](#block-validity)); cross-block distinctness within the retained
epoch window is specified in the Tachyon Shielded Protocol ZIP under
[Epochs](https://github.com/tachyon-zcash/zips/blob/37159f1bb23430ec07c5d731dece7f55d8bc90d3/zips/draft-tachyon-shielded-protocol.md#epochs) and
[Per-stamp checks](https://github.com/tachyon-zcash/zips/blob/37159f1bb23430ec07c5d731dece7f55d8bc90d3/zips/draft-tachyon-shielded-protocol.md#per-stamp-checks).

`proofTachyon` is the Ragu proof.
The statement it attests to, and the base rule that a stamp proof MUST verify
against the Tachyon statement, are specified in the Tachyon Shielded Protocol ZIP
under [Stamp](https://github.com/tachyon-zcash/zips/blob/37159f1bb23430ec07c5d731dece7f55d8bc90d3/zips/draft-tachyon-shielded-protocol.md#stamp),
[Proof tree](https://github.com/tachyon-zcash/zips/blob/37159f1bb23430ec07c5d731dece7f55d8bc90d3/zips/draft-tachyon-shielded-protocol.md#proof-tree), and
[Per-stamp checks](https://github.com/tachyon-zcash/zips/blob/37159f1bb23430ec07c5d731dece7f55d8bc90d3/zips/draft-tachyon-shielded-protocol.md#per-stamp-checks); how that rule
is applied to a block's stamps is specified in [Block validity](#block-validity).

### Pointer stamp

When `tachyonBundleState` is `0x02`, the pointer stamp follows the body, laid out as in the wire layout above.

`tachyonAggregateId` is the `wtxid` (ZIP 239 [^zip-0239]) of a covering transaction.
It MUST NOT be all zero; the rule applies to every pointer-stamped transaction, with or without actions.
Which transaction it must identify within a block is specified in [Block validity](#block-validity).

### Canonical encodings

* Every compactSize field MUST use the minimal encoding for its value (§ 7.1 ‘Transaction Encoding and Consensus’) and MUST NOT encode a value exceeding `0x02000000`.
  A parser MUST reject any other encoding.
* `cv` and `rk` are 32-byte compressed encodings of Pallas points.
  A parser MUST reject an encoding that does not decode to a point.
  `rk` MUST decode as a RedPallas validating key (§ 5.4.7 ‘RedDSA, RedJubjub, and RedPallas’).
  The identity point decodes successfully; it is excluded by the rule in [Action digests](#action-digests), not by the parser.
* `anchorTachyon` and each tachygram are canonical little-endian encodings of Pallas base field elements; a parser MUST reject an encoding whose value is not less than the field modulus.
* `vActionsTachyon` carries no ordering requirement: the descriptors may appear in any sequence the transaction author chooses.
  The signatures in `vActionSigsTachyon` follow their descriptors' positions regardless of that order.
* The tachygrams in `vTachygrams` MUST be in ascending lexicographic order of their 32-byte encodings; a parser MUST reject a stamp whose tachygrams are out of order.
  With the distinctness rule ([Proof stamp](#proof-stamp)) the sequence is strictly increasing.
* `cTachygrams` is a 32-byte compressed Vesta point; a parser MUST reject an encoding that does not decode to a point.
  Whether it commits the stamp's `vTachygrams` is a block-validity property ([Block validity](#block-validity)).
* `vMemoTachyon` is an opaque byte string at parse time; this ZIP imposes no structure on its contents.
* `hStampActionsTachyon` is an opaque 32-byte string at parse time; whether it matches the covered actions is a block-validity property ([Block validity](#block-validity)).
* Signatures (`vActionSigsTachyon`, `bindingSigTachyon`) are opaque 64-byte strings at parse time; their validity is a verification-time property.
* `proofTachyon` is exactly `PROOF_SIZE` bytes and MUST decode as a Ragu proof.
  The proof encoding is defined by the Ragu proof system.

### Transaction digest contributions

The bundle contributes one leaf to each of the transaction's two digest trees (ZIP 244 [^zip-0244]).
This section states what the bundle supplies to each; the leaf algorithms and personalizations are specified by ZIP 244 as extended for Tachyon ([Transaction digest contributions](zip-244.md#transaction-digest-contributions)).

The effecting contribution (to `txid` and the sighash) commits to `hActionsTachyon`, the descriptor digest over the bundle's own actions ([Action descriptor digests](#action-descriptor-digests)), to `valueBalanceTachyon`, and to `hMemoTachyon`, the digest of `vMemoTachyon`.
`hActionsTachyon` is distinct from `hStampActionsTachyon`, which may cover more actions than the bundle's own.
The stamp is excluded, so the contribution is invariant across stamping, merging, stripping, and re-stamping.

The authorizing contribution (to `auth_digest`) commits to `tachyonBundleState`, to the action and binding signatures, and to the stamp, the latter through the 64-byte `stamp_digest` whose algorithm the ZIP 244 update specifies: a proof stamp's covered-actions digest and remaining fields, or a pointer stamp's `tachyonAggregateId` directly.
The state byte separates the two stamp forms, whose contributions share the 64-byte shape.

A transaction with no Tachyon bundle contributes distinctly from a bundle with no actions: no bundle produces the empty preimage, while every bundle's effecting contribution contains its encoded balance and its authorizing contribution contains at least its binding signature and `stamp_digest`.

### Bundle validity

The rules owned by this ZIP, applying to a single transaction's bundle:

1. `tachyonBundleState` MUST be `0x00`, `0x01`, or `0x02`.
2. Every compactSize MUST be minimally encoded and MUST NOT exceed `0x02000000`.
3. Every point and field-element encoding MUST be canonical, and every sequence in canonical order, as specified in [Canonical encodings](#canonical-encodings).
4. An action's $\mathsf{cv}$ and $\mathsf{rk}$ MUST NOT be the identity point.
5. Every action signature MUST verify over the transaction sighash under its action's $\mathsf{rk}$.
6. `bindingSigTachyon` MUST verify over the transaction sighash under the derived $\mathsf{bvk}$.
7. `valueBalanceTachyon` MUST be in the range $-\mathrm{MAX\_MONEY}$ to $\mathrm{MAX\_MONEY}$ inclusive.
8. A bundle with no actions MUST have `valueBalanceTachyon` equal to $0$.
9. A proof stamp's `proofTachyon` MUST be exactly `PROOF_SIZE` bytes and a valid proof encoding.
10. A proof stamp's tachygrams MUST be distinct.
11. A pointer stamp's `tachyonAggregateId` MUST NOT be all zero.

Rules outside the scope of this ZIP are enumerated in [Non-requirements](#non-requirements).

### Block validity

The rules owned by this ZIP that constrain a block's Tachyon bundles together.
A validator enforces them fail-fast, in this order:

1. **Tachygram uniqueness.** All tachygrams in a block MUST be distinct.
   The block's tachygrams are the multiset union of the `vTachygrams` of every proof stamp, and a single scan enforces this rule and the per-bundle distinctness of [Bundle validity](#bundle-validity) rule 10 together; reject on any duplicate.
   Reuse across blocks within the retained epoch window is governed by the
   Tachyon Shielded Protocol ZIP's
   [Per-stamp checks](https://github.com/tachyon-zcash/zips/blob/37159f1bb23430ec07c5d731dece7f55d8bc90d3/zips/draft-tachyon-shielded-protocol.md#per-stamp-checks).
2. **Proof coverage.** Every pointer-stamped transaction MUST bear a `tachyonAggregateId` identifying a proof-stamped transaction in the same block; reject if absent or not proof-stamped.
   A pointer-stamped transaction with no actions satisfies this rule against any proof-stamped transaction in the block: it contributes no action descriptors to rule 3, so consensus attaches no further meaning to its reference.
3. **Covered-actions digest.** The descriptors collected across a proof stamp and every transaction it covers MUST be distinct, and the stamp's `hStampActionsTachyon` MUST match their descriptor digest.
   For each proof stamp, collect the descriptors of the bundle's own actions together with those of every pointer-stamped transaction naming it, sort them, and compute the descriptor digest ([Action descriptor digests](#action-descriptor-digests)); reject on any repeated descriptor, and on mismatch with the carried `hStampActionsTachyon`.
   The check is a sort and one BLAKE2b-256 hash, with no curve arithmetic.
4. **Tachygram commitment.** Every proof stamp's carried `cTachygrams` MUST commit that stamp's `vTachygrams`.
   Form the multiset commitment over the stamp's tachygrams ([Multiset commitments](#multiset-commitments)) and reject on mismatch with the carried point.
   The check is curve arithmetic, so it follows the cheaper descriptor checks of rule 3.
5. **Proof verification.** Every proof stamp MUST verify.
   The validator reassembles the stamp PCD from `proofTachyon`, `anchorTachyon`, the `cTachygrams` confirmed by rule 4, and `cStampActionsTachyon` formed over the confirmed action set's digests ([Action digests](#action-digests), [Multiset commitments](#multiset-commitments)); reject if any proof fails.
   The base requirement that a proof verifies the Tachyon statement is specified
   in the Tachyon Shielded Protocol ZIP's
   [Per-stamp checks](https://github.com/tachyon-zcash/zips/blob/37159f1bb23430ec07c5d731dece7f55d8bc90d3/zips/draft-tachyon-shielded-protocol.md#per-stamp-checks); this rule
   applies it per stamp within a block.

## Rationale

This subsection is non-normative.

### The stamp is excluded from the txid contribution

The effecting contribution excludes the stamp, so stamping, merging, stripping, and re-stamping preserve a transaction's logical identity.
This is the property the aggregation lifecycle rests on: a pointer-stamped transaction in a block is the same transaction its author signed.

### Zero-action balance

The v5 analogue omits `valueBalanceOrchard` when the action count is zero and defines its value as zero in that case.
Tachyon gates field presence on the bundle state, not the action count: the non-tachyon state omits the field, while a present bundle always encodes `valueBalanceTachyon`.
A present bundle with no actions therefore still carries the field, so the zero balance is stated as an explicit rule.

### Identity points are invalid

The action digest hashes affine coordinates, which the identity point lacks.
Excluding it also rejects a degenerate verification key and a degenerate value commitment.

### `hStampActionsTachyon` is sorted for reconstruction agreement

`hStampActionsTachyon` can cover many transactions' actions, combined by whatever merge tree an aggregator chose.
Sorting before hashing makes it a function of the covered multiset alone, so any party reconstructs the same digest regardless of merge history.
The multiset commitments ([Multiset commitments](#multiset-commitments)) get this order-independence for free, as polynomial multiplication.

### Covered actions are required to be distinct

Two identical descriptors carry an identical $\mathsf{rk}$, so the same signature would authorize both if they sign the same transaction sighash.
A descriptor digest can be computed over a collection containing duplicates, so digest agreement alone does not establish distinctness.
[Block validity](#block-validity) rule 3 therefore rejects repeated descriptors before digest comparison and proof verification.

### `vTachygrams` is sorted against `wtxid` malleability

The stamp is authorizing data that no signature covers ([Signatures survive stripping](#signatures-survive-stripping)), and the proof commits to `vTachygrams` order-independently, so only a canonical order pins its wire form.
Without one, an observer could reorder `vTachygrams` to mint a distinct `wtxid` for byte-identical semantic content.
Requiring sorted order gives it the one serialization that `vActionsTachyon` gets from its signature coverage instead.

### A flat hash, not an algebraic commitment, carries the covered actions

The carried field serves coverage identification and fail-fast confirmation.
The proof binds the action set through `cStampActionsTachyon`, which validators reconstruct from the confirmed actions, so the carried field needs no algebraic structure: a flat hash commits the covered multiset just as well and reconstructs with no curve arithmetic.

### Deterministic multiset commitments

The committed multisets are public data, so a hiding commitment is unnecessary; determinism is what lets any party recompute a commitment from the data it covers.

### Fixed-size proof

This draft assumes a proof size independent of the number of covered actions.
A constant-size proof field needs no length prefix.
The whole stamp is not constant-size: its tachygram vector grows with the published multiset.

### `wtxid`, not `txid`, in `tachyonAggregateId`

A `txid` is ambiguous across the authorization forms that share it; the `wtxid` pins the physical covering transaction, stamp included, which is what the pointer-stamped transaction needs to reference.

### Nonzero `tachyonAggregateId`

Every pointer-stamped bundle names a covering transaction, and the unassigned pointer state has no valid wire form.
The all-zero value is reserved for an unassigned pointer and is invalid on the wire.

## Security Implications

This subsection is non-normative.

### Canonical encodings, except action order

The canonical-encoding rules restrict how field values and the tachygram sequence are serialized; they do not imply that a transaction has only one valid proof or set of signatures.
Reordering distinct action descriptors changes `hActionsTachyon`, and therefore the sighash every signature covers, so existing signatures do not authorize the reordered transaction.
Leaving action order to the author's choice is the same property Sapling and Orchard rely on for their own unordered spend, output, and action arrays.
Authorization-form changes (re-stamping, stripping) produce distinct bundles by design and are reflected in `auth_digest` and `wtxid` (ZIP 239 [^zip-0239]).

### Duplicate actions are gated after parsing, not by the parser

The parser enforces no distinctness over `vActionsTachyon`, so a bundle carrying a repeated action descriptor parses.
Each descriptor's $\mathsf{cv}$ enters the binding sum, so action multiplicity is load-bearing and the parser cannot deduplicate without changing the asserted balance; the descriptor multiset is exactly what a stamp's proof commits to through `cStampActionsTachyon`.

[Block validity](#block-validity) rule 3 explicitly rejects repeated descriptors in a proof stamp's combined coverage before comparing the descriptor digest.
This includes duplicates within one bundle and across bundles covered by the same stamp.
The multiset commitment preserves repeated roots; it does not itself prohibit them.
A parser must therefore preserve multiplicity rather than silently deduplicate the actions.

`vTachygrams` is the opposite case.
Repeated tachygrams violate the explicit distinctness rule, which the parser enforces directly ([Bundle validity](#bundle-validity) rule 10).

### Balance consistency is enforced by the binding property

A valid binding signature establishes that `valueBalanceTachyon` equals the net value committed by the actions' $\mathsf{cv}$, by the same binding argument as Orchard (§ 4.14).

### Signatures survive stripping

All signatures cover the transaction sighash, which incorporates only effecting data.
A miner stripping a proof stamp changes no signed data, so aggregation does not invalidate signatures.
A signature authorizes only the sighash it signs; using an action in a transaction with different effecting data requires a new signature over that transaction's sighash.

<div class="note">

Parse validity is not spend validity.
A bundle that parses and whose signatures verify is not thereby valid to spend; the rules enumerated in [Non-requirements](#non-requirements) also apply.
Implementers and auditors should not assume the rules in this ZIP alone establish those properties.

</div>

## Privacy Implications

This subsection is non-normative.

### Public data

$\mathsf{cv}$ is a hiding commitment to the action's value.
The unlinkability of $\mathsf{rk}$ and tachygrams depends on the [Tachyon Shielded Protocol](https://github.com/tachyon-zcash/zips/blob/37159f1bb23430ec07c5d731dece7f55d8bc90d3/zips/draft-tachyon-shielded-protocol.md), not on their wire encoding.
The action count, the value balance, and, on a proof-stamped bundle, the tachygram count are public, as is anything derivable from them.

## Deployment

This ZIP is deployed with a Tachyon network upgrade.
Activation parameters are specified by the corresponding deployment ZIP ([Network Upgrade Deployment](network-upgrade-deployment.md)).

## Reference implementation

The `zcash_tachyon` crate in the
[Tachyon repository](https://github.com/tachyon-zcash/tachyon) provides the bundle
codec, commitment and digest calculations, and signature verification.
Experimental transaction-format, value-accounting, and transaction-digest
integration is provided by
[zakura-core/common PR #178](https://github.com/zakura-core/common/pull/178).
Experimental full-node integration, including bundle and block validation, is
provided by [Zakura PR #795](https://github.com/zakura-core/zakura/pull/795).

## References

[^BCP14]: [Information on BCP 14: "RFC 2119: Key words for use in RFCs to Indicate Requirement Levels" and "RFC 8174: Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words"](https://www.rfc-editor.org/info/bcp14)

[^protocol]: [Zcash Protocol Specification](https://zips.z.cash/protocol/protocol.pdf)

[^protocol-valuecommit]: [Zcash Protocol Specification, Version v2026.7.0-202-gafa086 [NU6.2]. Section 5.4.8.3: Homomorphic Pedersen commitments (Sapling and Orchard)](https://zips.z.cash/protocol/protocol.pdf#concretehomomorphiccommit)

[^protocol-orchardbalance]: [Zcash Protocol Specification, Version v2026.7.0-202-gafa086 [NU6.2]. Section 4.14: Balance and Binding Signature (Orchard)](https://zips.z.cash/protocol/protocol.pdf#orchardbalance)

[^zip-0200]: [ZIP 200: Network Upgrade Mechanism](https://zips.z.cash/zip-0200)

[^zip-0225]: [ZIP 225: Version 5 Transaction Format](https://zips.z.cash/zip-0225)

[^zip-0239]: [ZIP 239: Relay of Version 5 Transactions](https://zips.z.cash/zip-0239)

[^zip-0244]: [ZIP 244: Transaction Identifier Non-Malleability](https://zips.z.cash/zip-0244)

[^zip-0248]: [ZIP 248: Extensible Transaction Format](https://zips.z.cash/zip-0248)
