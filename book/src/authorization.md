# Authorization

A Tachyon bundle requires three layers of authorization: per-action signatures that bind each tachyaction to its tachygram, value commitments that hide individual values while preserving their algebraic sum, and a binding signature that proves the declared balance is correct.
This chapter covers each layer, then shows the complete flow from action creation through consensus.

## Per-action Signing

Each tachyaction requires a fresh randomized key pair.
The authorization flow starts with per-action entropy $\theta$ and diverges based on whether the action is a spend or output.

```mermaid
flowchart TB
    theta["theta (per-action entropy)"]
    cm["cm (note commitment)"]
    hash(("hash(theta, cm)"))

    theta & cm --- hash

    hash -->|"Tachyon-Spend"| spend_alpha
    hash -->|"Tachyon-Output"| output_alpha

    spend_alpha -->|"rk = ak + [alpha]G"| plan
    output_alpha -->|"rk = [alpha]G"| plan

    plan["plan { rk, note, theta, rcv, effect }"]
    plan ---|"bundle digest"| sighash((sighash))

    spend_alpha -->|"rsk = ask + alpha"| sign
    sighash --> sign
    output_alpha -->|"rsk = alpha"| sign

    sign(("sign(rsk, sighash)"))
    sign --- action["action { cv, rk, sig }"]
```

### ActionEntropy ($\theta$)

32 bytes of randomness chosen by the signer.
Combined with a note commitment to deterministically derive the randomizer $\alpha$:

$$\alpha_{\text{spend}} = \text{ToScalar}(\text{BLAKE2b-512}(\text{"Tachyon-Spend"},\; \theta \| \mathsf{cm}))$$

$$\alpha_{\text{output}} = \text{ToScalar}(\text{BLAKE2b-512}(\text{"Tachyon-Output"},\; \theta \| \mathsf{cm}))$$

Distinct personalizations prevent the same $(\theta, \mathsf{cm})$ pair from producing identical $\alpha$ values for spend and output actions.

This design enables **hardware wallet signing without proof construction**: the hardware wallet holds $\mathsf{ask}$ and $\theta$, signs with $\mathsf{rsk} = \mathsf{ask} + \alpha$, and a separate device constructs the proof later using $\theta$ and $\mathsf{cm}$ to recover $\alpha$.

### Spend vs Output

Both paths produce $\mathsf{rk}$ during the assembly phase, then sign the transaction sighash during the authorization phase.
The randomizer $\alpha$ is retained separately as a proof witness.

**Spend** — requires spending authority:

$$\mathsf{rsk} = \mathsf{ask} + \alpha$$

The resulting $\mathsf{rk} = \mathsf{ak} + [\alpha]\,\mathcal{G}$ is a re-randomization of the spend validating key.
During assembly, the user device derives $\mathsf{rk}$ from the public key $\mathsf{ak}$ (no $\mathsf{ask}$ needed).
During authorization, the custody device derives $\alpha$, computes $\mathsf{rsk}$, and signs the transaction sighash.

**Output** — no spending authority needed:

$$\mathsf{rsk} = \alpha$$

The resulting $\mathsf{rk} = [\alpha]\,\mathcal{G}$ is a re-randomization of the generator itself.
No custody device is involved.

Both produce an $\mathsf{rk}$ that can verify a signature, but only the spend's $\mathsf{rk}$ requires knowledge of $\mathsf{ask}$.
This unification lets consensus treat all tachyactions identically.

### Bundle commitment

The bundle commitment is a digest of the bundle's effect:

$$\mathsf{actions\_acc} = \sum_i H(\mathsf{cv}_i \| \mathsf{rk}_i)$$

The accumulator is order-independent (addition is commutative), so the bundle commitment does not depend on action ordering.

$$\mathsf{bundle\_commitment} = \text{BLAKE2b-512}(\text{"Tachyon-BndlHash"},\; \mathsf{action\_acc} \| \mathsf{v\_balance})$$

The stamp is excluded because it is stripped during [aggregation](./aggregation.md).
The same $\mathsf{action\_acc}$ appears in the Ragu PCD stamp header, binding the stamp to the same set of actions as the signatures.

### Transaction sighash

All signatures (action and binding) sign the same transaction-wide sighash.
The sighash is computed at the transaction layer, incorporating the bundle commitment from each pool (transparent, sapling, orchard, tachyon).
The tachyon crate contributes its bundle commitment; a transaction-level crate computes the sighash and passes it in as opaque bytes.

This binds every signature to the complete set of effecting data across all pools.
Since $\mathsf{rk}$ is itself a commitment to $\mathsf{cm}$ (via $\alpha$'s derivation from $\theta$ and $\mathsf{cm}$), the signature transitively binds each action to its tachygram without the tachygram appearing in the action.

| Key            | Lifetime   | Can sign? | Can verify? |
| -------------- | ---------- | --------- | ----------- |
| $\mathsf{ask}$ | Long-lived | No        | —           |
| $\mathsf{ak}$  | Long-lived | —         | No          |
| $\mathsf{rsk}$ | Per-action | **Yes**   | —           |
| $\mathsf{rk}$  | Per-action | —         | **Yes**     |

## Value Balance

Tachyon uses Pedersen commitments on the Pallas curve for value hiding:

$$\mathsf{cv} = [v]\,\mathcal{V} + [\mathsf{rcv}]\,\mathcal{R}$$

where $v$ is the signed integer value (positive for spends, negative for outputs) and $\mathsf{rcv}$ is a random trapdoor in $\mathbb{F}_q$.

$\mathsf{rcv}$ is currently sampled as a uniformly random scalar (`Fq::random`). This derivation may be revised in the future to incorporate a hash of the note commitment or other action-specific data.

The generators $\mathcal{V}$ and $\mathcal{R}$ are shared with Orchard, derived from the domain `z.cash:Orchard-cv`.
This reuse is intentional — the binding signature scheme uses `reddsa::orchard::Binding` which hardcodes $\mathcal{R}$ as its basepoint.

### Homomorphic property

The sum of value commitments preserves the algebraic structure:

$$\sum_i \mathsf{cv}_i = \bigl[\sum_i v_i\bigr]\,\mathcal{V} + \bigl[\sum_i \mathsf{rcv}_i\bigr]\,\mathcal{R}$$

This enables the binding signature scheme to prove value balance without revealing individual values.

### Binding signature

The binding signature proves that the bundle's value commitments are consistent with the declared $\mathsf{v\_balance}$.

**Signer** — knows every $\mathsf{rcv}_i$ and computes:

$$\mathsf{bsk} = \sum_i \mathsf{rcv}_i$$

The signer signs the transaction sighash with $\mathsf{bsk}$.

**Validator** — knows each $\mathsf{cv}_i$ (from actions) and $\mathsf{v\_balance}$ (from the bundle), and reconstructs the corresponding public key:

$$\mathsf{bvk} = \sum_i \mathsf{cv}_i - [\mathsf{v\_balance}]\,\mathcal{V}$$

Expanding the commitments $\mathsf{cv}_i = [v_i]\,\mathcal{V} + [\mathsf{rcv}_i]\,\mathcal{R}$:

$$\mathsf{bvk} = \bigl[\sum_i v_i - \mathsf{v\_balance}\bigr]\,\mathcal{V} + \bigl[\sum_i \mathsf{rcv}_i\bigr]\,\mathcal{R}$$

When $\sum_i v_i = \mathsf{v\_balance}$, the $\mathcal{V}$ component vanishes:

$$\mathsf{bvk} = [\mathsf{bsk}]\,\mathcal{R}$$

So $\mathsf{bsk}$ is the discrete log of $\mathsf{bvk}$ with respect to $\mathcal{R}$ — exactly what the signature proves.
If the values don't balance, the $\mathcal{V}$ term survives and the signer cannot produce a valid signature (by the binding property of the Pedersen commitment).

## End-to-end Flow

A bundle plan feeds three independent paths that converge in the final bundle.
Each path consumes the same action plans but produces a different component of the bundle:

- **Proving** — each action plan yields a leaf stamp; leaves merge into a single Ragu PCD stamp.
- **Signing** — custody derives $\mathsf{rsk}$ per spend action and signs the transaction sighash; output actions are signed by the user device.
- **Binding** — the bundle commitment (from $\mathsf{action\_acc}$ and $\mathsf{v\_balance}$) feeds into the transaction sighash, which the binding key signs.

Consensus recomputes $\mathsf{action\_acc}$ from the visible actions and checks it against both the sighash (via the bundle commitment) and the stamp (via the PCD header).
A modified action breaks both checks.

```mermaid
flowchart LR
    style proving fill:#ff000010,stroke:none
    style authorization fill:#ff000010,stroke:none
    style binding fill:#ff000010,stroke:none

    style custody fill:#00ff0010
    style prover fill:#00ff0010

    style pczt fill:#0000ff10
    style tx fill:#0000ff10


    subgraph pczt[partial tx]
        subgraph bundle_plan["bundle plan"]
            action_plan@{ shape: st-rect, label: "action plan" }
            value_balance
        end
        other1@{ shape: st-doc, label: "other tx data" } 
    end
    pczt ~~~ sighash{sighash}
    bundle_plan & other1 === sighash 


    value_balance --> value_balance_2[value_balance]

    subgraph tx[complete tx]
        subgraph bundle["stamped bundle"]
            value_balance_2[value_balance]
            action@{ shape: st-rect }
            binding_sig
            stamp
        end
        other2@{ shape: st-doc, label: "other tx data" }
    end



    subgraph proving["proving flow"]
        leaf@{ shape: st-rect, label: "leaf" }
        subgraph prover["proving device"]
            merge((merge))
        end
    end
    action_plan --- leaf --- merge --> stamp


    sighash ~~~ binding
    subgraph binding["binding flow"]
        bsk 
        sign_binding_sig(("sign"))
    end
    action_plan & value_balance --- bsk --- sign_binding_sig ==> binding_sig
    sighash === sign_binding_sig

    sighash ~~~ authorization
    subgraph authorization["authorization flow"]
        subgraph custody["custody device"]
            rsk@{ shape: st-rect }
            sign_action((("sign")))
        end
    end
    sighash === sign_action
    action_plan --- rsk --- sign_action ==> action

    other1 --> other2
    pczt ~~~ sighash
```

Transaction construction is split into three phases: **assembly** (create action plans with $\mathsf{rk}$ and $\mathsf{rcv}$; $\mathsf{cv}$ is derived on demand), **commitment** (derive $\mathsf{cv}$ from each plan and compute the bundle commitment), and **authorization** (custody independently derives $\mathsf{cv}$, computes the sighash, and signs spend actions).
Signing and stamping run in parallel — stamping depends only on the action plans and anchor, not on signatures or the sighash.

A single user device may act as custody and stamper, but the trust boundary is only required to cover custody and the user device.

```mermaid
sequenceDiagram

actor User

activate User

    note over User: select/create notes { pk, psi, rcm, v }

rect rgb(100, 149, 237, 0.1)
    loop per action

        note over User: random theta
        note over User: random rcv
        note over User: cm = NoteCommit(pk, psi, rcm, v)
        alt spend
            note over User: alpha = Blake2b("Tachyon-Spend", theta || cm)
            note over User: rk = ak + [alpha]G
            note over User: cv = ValueCommit(v, rcv)
        else output
            note over User: alpha = Blake2b("Tachyon-Output", theta || cm)
            note over User: rk = [alpha]G
            note over User: cv = ValueCommit(-v, rcv)
        end
        note over User: action_plan { rk, note, theta, rcv, effect }
    end

    note over User: bundle_plan { action_plan[], v_balance }


end

loop per output action
    note over User: sig = Sign(alpha, sighash)
end
note over User: bsk = Sum rcv_i
note over User: binding_sig = Sign(bsk, sighash)


par Authorization
    rect rgb(255, 165, 0, 0.1)

        create participant Custody@{ type: "boundary" }

        User ->> Custody: bundle_plan, binding_sig, output_sigs, tx etc

        loop per action
            alt spend
                note over Custody: cv = ValueCommit(v, rcv)
            else output
                note over Custody: cv = ValueCommit(-v, rcv)
            end
            note over Custody: action_digest = H(cv || rk)
        end
        note over Custody: action_acc = Sum action_digest_i
        note over Custody: bundle_commitment = Blake2b("Tachyon-BndlHash", action_acc || v_balance)
        note over Custody: compute sighash

        break
            note over Custody: validate output_sigs
            note over Custody: validate binding_sig
        end

        loop per spend action
            note over Custody: alpha = Blake2b("Tachyon-Spend", theta || cm)
            note over Custody: rsk = ask + alpha
            note over Custody: sig = Sign(rsk, sighash)
        end
        destroy Custody
        Custody -->> User: action_sigs, tx sigs
        note over User: apply signatures
    end

and Proving 
    rect rgb(138, 43, 226, 0.1)
        note over User: select anchor

        loop per action
        critical anchor, action plan { rk, note, theta, rcv, effect }, pak { ak, nk }
                alt effect == spend
                    User --> User: rk == ak + [alpha]G
                    note over User: flavor = epoch(anchor)
                    note over User: tachygram_acc = PRF(nk, psi, flavor)
                else effect == output
                    User --> User: rk == [alpha]G
                    note over User: tachygram_acc = NoteCommit(pk, psi, rcm, v)
                end
                note over User: action_acc = H(cv || rk)
                note over User: pcd: leaf stamp(action_acc, tachygram_acc, anchor)
            end
        end

        create participant Stamper
        User ->> Stamper: leaf stamps, tachygrams


        loop while stamps > 1
            critical left(action_acc, tachygram_acc, anchor), right(action_acc, tachygram_acc, anchor)
                note over Stamper: action_acc = union(left.action_acc, right.action_acc)
                note over Stamper: tachygram_acc = union(left.tachygram_acc, right.tachygram_acc)
                note over Stamper: anchor = intersect(left.anchor, right.anchor)
                note over Stamper: pcd: stamp(action_acc, tachygram_acc, anchor)
            end
        end
        destroy Stamper
        Stamper ->> User: stamp(tachygram_acc, action_acc, anchor)

        break
            note over User: verify stamp(tachygram_acc, action_acc, anchor)
        end
    end
end



create participant Consensus
note over User: transaction { actions[], v_balance, binding_sig, stamp } 
deactivate User
destroy User
User ->> Consensus: transaction
break
    note over Consensus: action_acc = Sum H(cv_i || rk_i)
    note over Consensus: bundle_commitment = Blake2b("Tachyon-BndlHash", action_acc || v_balance)
    note over Consensus: compute sighash
    note over Consensus: check action sigs against sighash
    note over Consensus: check binding sig against sighash
    note over Consensus: verify stamp(tachygram_acc, action_acc, anchor)
end
```

