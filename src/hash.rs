
use curve25519_dalek::scalar::Scalar;
use sha2::{Sha512, Digest};

use std::io;
use std::io::{Read,BufReader};

pub fn read_chunk(reader: &mut dyn Read, len: usize) -> Result<Vec<u8>, io::Error> {

    let mut result = vec![0u8; len];

    let mut i = 0;

    while i < len {
        let n = match reader.read(&mut result[i..len]) {
            Ok(n) => n,
            Err(e) => {
                println!("errored");
                return Err(e.into())
            }
        };
        i += n;

        if n == 0 {
            break;
        }
    }
    // In case the total bytes read is smaller than expected,
    // (EOF or last block in the file).
    result.truncate(i);

    Ok(result)
}


pub fn hash_message<In: Read>(msg_in: &mut In) -> Result<Scalar, io::Error> {
    let mut reader = BufReader::new(msg_in);
    let mut hasher = Sha512::new();

    loop {
        let block = read_chunk(&mut reader, 32)?;

        if block.len() < 32 {
            hasher.input(block);
            break;
        }

        hasher.input(block);
    }
    let c = Scalar::from_hash(hasher);

    Ok(c)
}

