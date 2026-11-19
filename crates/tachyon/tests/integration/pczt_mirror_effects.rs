use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    bundle,
    pczt::{
        self,
        mirror::{EncodingCause, Field, ParseError},
    },
};

use super::fixtures::wallet::{WalletSim, output_plan, shared_sk};

#[test]
fn pczt_mirror_decodes_effect_fields_and_locates_invalid_action_bytes() {
    let rng = &mut StdRng::seed_from_u64(12);
    let wallet = WalletSim::new(shared_sk());
    let plan = bundle::Plan::new(
        vec![],
        vec![output_plan(rng, wallet.random_note(100))],
        wallet.random_note(10),
        vec![],
    )
    .unwrap();
    let mut mirror = pczt::Bundle::from_plan(&plan).to_mirror();
    assert_eq!(
        pczt::Bundle::parse(mirror.clone()).unwrap().to_mirror(),
        mirror
    );
    mirror.actions[0].theta = Some([u8::MAX; 32]);
    assert!(matches!(
        pczt::Bundle::parse(mirror),
        Err(ParseError::InvalidEncoding(
            Field::Theta(0),
            EncodingCause::Noncanonical
        ))
    ));
}
