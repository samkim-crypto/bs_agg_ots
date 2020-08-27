
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::CompressedRistretto;

use sha2::{Sha512, Digest};

use super::*;
use hash::*;
use bs_signature::*;


/// Instantiation of the aggregate signature trait for the Bellare-Shoup
/// signature scheme
impl AggSigScheme for BSscheme {
    fn sig_aggregate<In: Read>(
        pks: Vec<Self::PK>,
        msgs: Vec<In>,
        sigs: Vec<Self::SG>
    ) -> Result<Self::SG> {
        let n = pks.len();

        if msgs.len() != n || sigs.len() != n {
            panic!("Size mismatch!");
        }

        let (seed, _) = hash_keys_msgs(&pks, msgs)?;

        let mut agg_sig = Scalar::from_bits([0u8; 32]);
        for i in 0..n {
            let mut hasher = Sha512::new();

            hasher.input(&seed);
            hasher.input([i as u8]);
            let ti = Scalar::from_hash(hasher);

            let BSsig(s) = sigs[i];

            agg_sig += ti * s;
        }

        Ok(BSsig(agg_sig))
    }

    fn aggregate_verify<In: Read>(
        pks: Vec<Self::PK>,
        msgs: Vec<In>,
        agg_sig: Self::SG
    ) -> Result<bool> {
        let n = pks.len();

        if msgs.len() != n {
            panic!("Size mismatch!");
        }

        let (seed, msg_hashes) = hash_keys_msgs(&pks, msgs)?;

        let mut ver_pks = vec![];
        for (i, c) in msg_hashes.iter().enumerate() {
            let BSpk(y0, y1) = pks[i];

            let y0 = y0.decompress().unwrap();
            let y1 = y1.decompress().unwrap();

            ver_pks.push(c * y0 + y1);
        }

        let g = CompressedRistretto::from_slice(&GENERATOR_SEED)
            .decompress()
            .unwrap();

        let mut agg_gc = Scalar::from_canonical_bytes([0u8; 32]).unwrap() * g;

        for (i, gc) in ver_pks.iter().enumerate() {
            let mut hasher = Sha512::new();

            hasher.input(&seed);
            hasher.input([i as u8]);
            let ti = Scalar::from_hash(hasher);

            agg_gc += ti * gc;
        }

        let BSsig(agg_s) = agg_sig;

        Ok(agg_s * g == agg_gc)
    }

}

pub fn hash_keys_msgs<K: Key, In: Read>(keys: &Vec<K>, mut msgs: Vec<In>) 
-> Result<(Vec<u8>, Vec<Scalar>)> {
    if msgs.len() != msgs.len() {
        panic!("Size mismatch");
    }

    let mut hasher = Sha512::new();

    // Hash public keys
    for (i, key) in keys.iter().enumerate() {
        hasher.input([i as u8]);
        hasher.input(key.hash_key());
    }

    let mut msg_hashes = Vec::with_capacity(msgs.len());

    // Hash messages
    for (i, msg) in msgs.iter_mut().enumerate() {
        hasher.input([i as u8]);

        let c = hash_message(msg)?;

        msg_hashes.push(c);
        hasher.input(c.as_bytes());
    }

    Ok((hasher.result().as_slice().into(), msg_hashes))
}
