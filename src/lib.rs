/// Bellare-Shoup One-Time Signatures and Signature Aggregation
///
/// This is a research prototype and should nver be used for important data
///
///
/// This library contains some prototype implementations of bellare-shoup one-time aggregatable
/// signature scheme. These are cryptographic digital signatures that have aggregatable properties:
/// one can aggregate multiple signatures into a single short digital signature.
///
/// For the accompanying research paper, see: https://crypto.stanford.edu/~skim13/agg_ots.pdf.
///
/// Basic traits that model digital signatures and aggregatable digital signatures are specified in
/// lib.rs. Instantiation of these traits for the Bellare-Shoup one-time signature scheme can be
/// found in bs_signature.rs and bs_aggregate.rs.

#[macro_use]
extern crate error_chain;

use std::io::{Read, Write};
use std::fmt::Debug;

pub mod errors {
    error_chain! {
        foreign_links {
            Io(::std::io::Error);
        }
    }
}

use errors::*;

#[macro_use]
pub mod bs_signature;
pub mod bs_aggregate;
pub mod profile;
pub mod hash;

/// Trait for cryptographic keys
pub trait Key: PartialEq + Clone + Debug + Sized {
    fn read_key<In: Read>(key_in: &mut In) -> Result<Self>;
    fn write_key<Out: Write>(&self, key_out: &mut Out) -> Result<()>;
    fn hash_key(&self) -> Vec<u8>;
}

/// Trait for digital signatures
pub trait Signature: PartialEq + Clone + Debug + Sized {
    fn read_sig<In: Read>(sig_in: &mut In) -> Result<Self>;
    fn write_sig<Out: Write>(&self, sig_out: &mut Out) -> Result<()>;
}

/// Trait for digital signatures algorithms
pub trait SigScheme {
    // Types for the secret key, public key, and digital signatures
    type SK: Key;
    type PK: Key;
    type SG: Signature;

    /* Generates a new, random secret-public key pair */
    fn keygen() -> Result<(Self::SK, Self::PK)>;

    /* Given a secret key and a message, generate a digital signature */
    fn sign<In: Read>(sk: Self::SK, msg_in: &mut In) 
        -> Result<Self::SG>;

    /* Given a public key, message, and signature, verify the signature */
    fn verify<In: Read>(pk: Self::PK, msg_in: &mut In, sig: Self::SG) 
        -> Result<bool>;
}

/// Trait for signature aggregation algorithms
pub trait AggSigScheme: SigScheme {

    /* Given a vector of public keys, messages, and signatures, produce a short
     * aggregate signature */
    fn sig_aggregate<In: Read>(
        pks: Vec<Self::PK>,
        msgs: Vec<In>,
        sigs: Vec<Self::SG>
    ) -> Result<Self::SG>;

    /* Given a vector of public keys, messages, and a signature, verify the
     * signature */
    fn aggregate_verify<In: Read>(
        pks: Vec<Self::PK>,
        msgs: Vec<In>,
        agg_sig: Self::SG
    ) -> Result<bool>;
}
