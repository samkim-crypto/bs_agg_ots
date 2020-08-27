extern crate rand_core;
extern crate sha2;

use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::CompressedRistretto;

use rand_core::OsRng;
use sha2::{Sha512, Digest};

use std::io::{Read,Write};

use super::*;
use hash::*;

/// Hard-coded randomness seed for the underlying Ristretto group.
pub static GENERATOR_SEED: [u8; 32] = 
    [184, 210, 96, 68, 141, 211, 10, 21,
     255, 86, 192, 240, 50, 22, 236, 201,
     209, 191, 168, 179, 52, 211, 105, 177,
     114, 197, 121, 84, 63, 105, 43, 80];

/// Secret key for the Bellare-Shoup signature scheme
#[derive(Clone, Debug, PartialEq)]
pub struct BSsk(pub Scalar, pub Scalar);

impl Key for BSsk {
    fn read_key<In: Read>(key_in: &mut In) -> Result<Self> {
        let mut x0_bytes = [0u8; 32];
        let mut x1_bytes = [0u8; 32];

        key_in.read_exact(&mut x0_bytes)?;
        key_in.read_exact(&mut x1_bytes)?;

        let x0 = Scalar::from_canonical_bytes(x0_bytes).unwrap();
        let x1 = Scalar::from_canonical_bytes(x1_bytes).unwrap();

        Ok(BSsk(x0, x1))
    }
 
    fn write_key<Out: Write>(&self, key_out: &mut Out) -> Result<()> {
        let x0_bytes = (self.0).as_bytes();
        let x1_bytes = (self.1).as_bytes();

        key_out.write_all(x0_bytes)?;
        key_out.write_all(x1_bytes)?;

        Ok(())
    }

    fn hash_key(&self) -> Vec<u8> {
        let hasher = Sha512::new();

        let BSsk(x0, x1) = self;
        hasher
            .chain(x0.as_bytes())
            .chain(x1.as_bytes())
            .result()
            .as_slice().
            into()
    }

}

/// Public key for the Bellare-Shoup signature scheme
#[derive(Clone, Debug, PartialEq)]
pub struct BSpk(pub CompressedRistretto, pub CompressedRistretto);

impl Key for BSpk {
    fn read_key<In: Read>(key_in: &mut In) -> Result<Self> {
        let mut y0_bytes = [0u8; 32];
        let mut y1_bytes = [0u8; 32];

        key_in.read_exact(&mut y0_bytes)?;
        key_in.read_exact(&mut y1_bytes)?;

        let y0 = CompressedRistretto::from_slice(&y0_bytes);
        let y1 = CompressedRistretto::from_slice(&y1_bytes);

        Ok(BSpk(y0, y1))
    }

    fn write_key<Out: Write>(&self, key_out: &mut Out) -> Result<()> {
        let y0_bytes = (self.0).as_bytes();
        let y1_bytes = (self.1).as_bytes();

        key_out.write_all(y0_bytes)?;
        key_out.write_all(y1_bytes)?;

        Ok(())
    }

    fn hash_key(&self) -> Vec<u8> {
        let hasher = Sha512::new();

        let BSpk(y0, y1) = self;
        hasher
            .chain(y0.as_bytes())
            .chain(y1.as_bytes())
            .result()
            .as_slice().
            into()
    }
}


/// Signature for the Bellare-Shoup signature scheme
#[derive(Clone, Debug, PartialEq)]
pub struct BSsig(pub Scalar);

impl Signature for BSsig {
    fn read_sig<In: Read>(sig_in: &mut In) -> Result<Self> {
        let mut sig_bytes = [0u8; 32];
        sig_in.read_exact(&mut sig_bytes)?;

        let sig = Scalar::from_canonical_bytes(sig_bytes).unwrap();

        Ok(BSsig(sig))
    }

    fn write_sig<Out: Write>(&self, sig_out: &mut Out) -> Result<()> {
        let sig_bytes = (self.0).to_bytes();
        sig_out.write_all(&sig_bytes)?;

        Ok(())
    }
}

/// Instantiation of the digital signature trait for the Bellare-Shoup
/// signature scheme
pub struct BSscheme;

impl SigScheme for BSscheme {
    type SK = BSsk;
    type PK = BSpk;
    type SG = BSsig;

    fn keygen() ->  Result<(BSsk, BSpk)> {
        let mut rng = OsRng;

        let g = CompressedRistretto::from_slice(&GENERATOR_SEED)
            .decompress()
            .unwrap();

        // Generate random exponents
        let x0 = Scalar::random(&mut rng);
        let x1 = Scalar::random(&mut rng);

        // Compute public key
        let y0 = x0 * g;
        let y1 = x1 * g;

        // Compress group elements
        let y0 = y0.compress();
        let y1 = y1.compress();

        let sk = BSsk(x0, x1);
        let pk = BSpk(y0, y1);

        Ok((sk, pk))
    }

    fn sign<In: Read>(sk: Self::SK, msg_in: &mut In)
        -> Result<BSsig> {

        // Read message and hash to a Scalar
        let c = hash_message(msg_in)?;

        // Compute c * x0 + x1
        let BSsk(x0, x1) = sk;
        let sig = c * x0 + x1;

        Ok(BSsig(sig))
    }

    fn verify<In: Read>(pk: Self::PK, msg_in: &mut In, sig: Self::SG) 
        -> Result<bool> {
        // Read message and hash to Scalar
        let c = hash_message(msg_in)?;

        // Compute y0^c + y1
        let g = CompressedRistretto::from_slice(&GENERATOR_SEED)
            .decompress()
            .unwrap();

        // Decompress into a Ristretto points
        let BSsig(s) = sig;
        let BSpk(y0, y1) = pk;

        let y0 = y0.decompress().unwrap();
        let y1 = y1.decompress().unwrap();

        Ok(s * g == c * y0 + y1)
    }
}

