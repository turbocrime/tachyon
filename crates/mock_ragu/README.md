# Mock Ragu 

This readme is primarily for coding agents.

Ragu provides recursive **Proof-Carrying Data** (PCD).

Proof-carrying data is simply a SNARK (proof) with information representing a specific claim (data).

This guide covers a simplified API surface relevant to this mock.

**All code blocks are pseudocode.** Check the actual source to identify the mock signatures and types.

## Proof-Carrying Data

Ragu `Pcd` is created by a series of `Steps` executed by an `Application`.

The `proof` represents the correctness of every executed step.

All step witnesses and step input headers are privately encoded inside `proof`, and are not available.

The final step's output header is the `data`.

```pseudocode
Pcd {
    proof, // opaque proof
    data   // final step output header
}
```

The `proof` and `data` together make the `Pcd`.

### Verifying

The `Pcd::verify` method is executed to confirm the proof's claim about the data is true.

For our purposes, after proving, `Pcd` is separated.

- The `proof` component is directly published by the prover.
- The `data` component must be reconstructed by verifiers from other published data.

Once reconstructed, the verifier uses `Proof::carry` to recreate `Pcd` and then `Pcd::verify` the proof.

## API

### `seed` — entry

```pseudocode
app.seed(step, witness) -> (step::Proof, step::Aux)
```

Executes a leaf step with no prior steps.
Returns a `Proof` and `Aux` as defined by the step.

### `fuse` — recurse

```pseudocode
app.fuse(step, witness, left_pcd, right_pcd) -> (step::Proof, step::Aux)
```

Executes a step with some prior steps.
Returns a `Proof` and `Aux` as defined by the step.

### `carry` — attach data

```pseudocode
proof.carry(data) -> Pcd
```

Attaches an output header data to a bare `Proof` to form a `Pcd`.
The resulting `Pcd` is passed to the next `fuse()` call or to `verify()`.

### `rerandomize` — blind the proof

```pseudocode
app.rerandomize(pcd) -> Pcd
```

Produces a new `Pcd` with a proof that verifies for the same data, but is cryptographically opaque.
Only the proof changes, the data stays the same.

### `verify`

```pseudocode
app.verify(pcd) -> bool
```

Verifies the PCD's proof and data are correct.

## Steps

In **mock_ragu**, the `Step` trait is simplified, and this description is even simpler.

The `Step::witness` method describes step execution inside the application.

```pseudocode
trait Step {
    const INDEX: Index; // unique in application

    type Left;          // output header of another step
    type Right;         // output header of another step
    type Output;        // this step's output header

    type Witness;       // private input
    type Aux;           // arbitrary extra output

    fn witness(
        witness: Witness,
        left: Left,
        right: Right,
    ) -> (Output, Aux);
}
```

### `Aux`

Arbitrary information provided by a `Step` to the prover.

`Aux` is the **only way** to send information from inside the proof execution back to the caller of `fuse()`/`seed()`.

It does not necessarily represent any input or output header, but the designer of an application may intend that it should be used to reconstruct the output header `data` ultimately carried by the `proof` to create the `Pcd` representation.

```pseudocode
let (proof, aux) = app.fuse(step, witness, left_pcd, right_pcd)?;
let data = reconstruct_output_header(aux, other_stuff);
app.verify(proof.carry(data))
```

## Example flow

### On the prover 

```pseudocode
(leaf_a, aux_a) = app.seed(leaf_step, leaf_witness_b)
data_a = reconstruct_leaf(aux_a, ...)
pcd_a = proof_a.carry(data_a)
pcd_a = app.rerandomize(pcd_a)

(leaf_b, aux_b) = app.seed(leaf_step, leaf_witness_a)
data_b = reconstruct_leaf(aux_b, ...)
pcd_b = proof_b.carry(data_b)
pcd_b = app.rerandomize(pcd_b)

(merged, aux_m) = app.fuse(next_step, next_witness, pcd_a, pcd_b)
data_m = reconstruct_merge(aux_m, ...)
pcd_m = merged.carry(data_m)
pcd_m = app.rerandomize(pcd_m)

publish_to_verifier(pcd_m.proof)
```

### On the verifier

```pseudocode
claim_proof = receive_from_prover()
claim_data = reconstruct_merge_from_public(public_stuff)
pcd_claim = claim_proof.carry(claim_data)
app.verify(pcd_claim)
```
