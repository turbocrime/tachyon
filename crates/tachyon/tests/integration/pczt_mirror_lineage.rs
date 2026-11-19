use rand::{SeedableRng as _, rngs::StdRng};
use udon::field::Field as _;
use zcash_tachyon::{
    BlockHeight, action, bundle,
    digest::poseidon::nf_master,
    effect,
    entropy::ActionEntropy,
    pasta::Fp,
    pczt::{
        self,
        mirror::{ActionWitness, SpendLineage},
    },
    value,
};

use super::fixtures::{
    application,
    pool::PoolSim,
    wallet::{WalletSim, shared_sk},
};

#[test]
fn pczt_mirror_round_trips_spend_lineage() {
    let rng = &mut StdRng::seed_from_u64(42);
    let app = &application();
    let wallet = WalletSim::new(shared_sk());
    let note = PoolSim::shared_note(1000);
    let secret = wallet.note_secret(app, note);
    let spendable = wallet.spendable_init(app, PoolSim::shared(), &note, BlockHeight(1));
    let mut secret_bytes = Vec::new();
    secret_bytes.extend(Fp::from(note.commitment()).to_bytes());
    secret_bytes.extend(Fp::from(note.pk).to_bytes());
    secret_bytes.extend(u64::from(note.value).to_le_bytes());
    secret_bytes.extend(Fp::from(note.psi).to_bytes());
    secret_bytes.extend(Fp::from(note.rcm).to_bytes());
    secret_bytes.extend(nf_master(note.psi.into(), wallet.pak.nk.into()).to_bytes());
    secret_bytes.extend(secret.proof().to_bytes().unwrap());
    let &(cm, epoch, anchor) = spendable.data();
    let mut spendable_bytes = Vec::new();
    spendable_bytes.extend(Fp::from(cm).to_bytes());
    spendable_bytes.extend(u32::from(epoch).to_le_bytes());
    anchor.write(&mut spendable_bytes).unwrap();
    spendable_bytes.extend(spendable.proof().to_bytes().unwrap());

    let spend = action::Plan::<effect::Spend> {
        note,
        theta: ActionEntropy::random(rng),
        rcv: value::Trapdoor::random(rng),
        authority: wallet.pak.ak,
    };
    let plan = bundle::Plan::new(vec![spend], vec![], wallet.random_note(10), vec![]).unwrap();
    let mut mirror = pczt::Bundle::from_plan(&plan).to_mirror();
    let Some(ActionWitness::Spend(mut witness)) = mirror.actions[0].witness.take() else {
        unreachable!()
    };
    witness.pak = Some([witness.ak.unwrap(), Fp::from(wallet.pak.nk).to_bytes()]);
    witness.lineage = Some(SpendLineage {
        secret: secret_bytes,
        spendable: spendable_bytes,
        spans: vec![],
    });
    mirror.actions[0].witness = Some(ActionWitness::Spend(witness));
    assert_eq!(
        pczt::Bundle::parse(mirror.clone()).unwrap().to_mirror(),
        mirror
    );
}
