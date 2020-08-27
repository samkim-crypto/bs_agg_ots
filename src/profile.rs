
extern crate rand;
extern crate time;

use super::*;
use bs_signature::*;

use std::fs::File;
use std::io::{Write,BufReader,BufWriter};

pub fn profile_run_all(iterations: usize, msg_size: usize, agg_num: usize) -> Result<()> {
    profile_signature(iterations, msg_size)?;
    profile_aggregation(iterations, msg_size, agg_num)?;

    Ok(())
}

pub fn profile_signature(iterations: usize, msg_size: usize) -> Result<()> {
    let gen_rand_msg = &|| -> Result<()> {

        let msg = random_vec(msg_size);

        let f = File::create("msg")?;
        let mut writer = BufWriter::new(f);

        writer.write_all(format!("{:?}", msg).as_bytes())?;

        Ok(())
    };

    let profile_keygen = &|| -> Result<(BSsk, BSpk, u64)> {
        let start = time::precise_time_ns();
        let (sk, pk) = BSscheme::keygen()?;
        let end = time::precise_time_ns();

        let time = end - start;

        Ok((sk, pk, time))
    };

    let profile_sign = &|sk| -> Result<(BSsig, u64)> {
        let f = File::open("msg")?;
        let mut msg = BufReader::new(f);

        let start = time::precise_time_ns();
        let sig = BSscheme::sign(sk, &mut msg)?;
        let end = time::precise_time_ns();

        let time = end - start;

        Ok((sig, time))
    };

    let profile_verify = &|pk, sig| -> Result<(bool, u64)> {
        let f = File::open("msg")?;
        let mut msg = BufReader::new(f);

        let start = time::precise_time_ns();
        let result = BSscheme::verify(pk, &mut msg, sig)?;
        let end = time::precise_time_ns();

        let time = end - start;

        Ok((result, time))
    };

    let mut cum_keygen_time = 0;
    let mut cum_sign_time = 0;
    let mut cum_verify_time = 0;

    for _ in 0..iterations {
        gen_rand_msg()?;

        let (sk, pk, keygen_time) = profile_keygen()?;

        let (sig, sign_time) = profile_sign(sk)?;

        let (_, verify_time) = profile_verify(pk, sig)?;

        cum_keygen_time += keygen_time;
        cum_sign_time += sign_time;
        cum_verify_time += verify_time;
    }
    std::fs::remove_file("msg")?;

    let average_keygen_time = cum_keygen_time / (iterations as u64);
    let average_sign_time = cum_sign_time / (iterations as u64);
    let average_verify_time = cum_verify_time / (iterations as u64);

    println!("Measuring Bellare-Shoup Signatures\n");
    println!("Iterations: {}", iterations);
    println!("Message size: {}\n", msg_size);
    println!("Average keygen time: {:?} ns", average_keygen_time);
    println!("Average sign time: {:?} ns", average_sign_time);
    println!("Average verify time: {:?} ns\n", average_verify_time);

    Ok(())
}

pub fn profile_aggregation(iterations: usize, msg_size: usize, agg_num: usize) -> Result<()> {
    let gen_rand_msg = &|agg_num| -> Result<()> {
        for i in 0..agg_num {
            let msg = random_vec(msg_size);
            let s = format!("msg-{}", i);

            let f = File::create(s)?;
            let mut writer = BufWriter::new(f);

            writer.write_all(format!("{:?}", msg).as_bytes())?;
        }

        Ok(())
    };

    let profile_setup = &|agg_num| -> Result<(Vec<BSpk>, Vec<BSsig>)> {
        let mut pks = vec![];
        let mut sigs = vec![];

        for i in 0..agg_num {

            let s = format!("msg-{}", i);
            let f = File::open(s)?;
            let mut msg = BufReader::new(f);

            let (sk, pk) = BSscheme::keygen()?;
            let sig = BSscheme::sign(sk, &mut msg)?;

            pks.push(pk);
            sigs.push(sig);
        }

        Ok((pks, sigs))
    };

    let profile_sig_aggregate = &|pks, sigs, agg_num| -> Result<(BSsig, u64)> {
        let mut msgs = vec![];
        for i in 0..agg_num {
            let s = format!("msg-{}", i);
            let f = File::open(s)?;
            let msg = BufReader::new(f);

            msgs.push(msg);
        }

        let start = time::precise_time_ns();
        let agg_sig = BSscheme::sig_aggregate(pks, msgs, sigs)?;
        let end = time::precise_time_ns();

        let time = end - start;

        Ok((agg_sig, time))
    };

    let profile_agg_verify = &|pks, asig, agg_num| -> Result<(bool, u64)> {
        let mut msgs = vec![];
        for i in 0..agg_num {
            let s = format!("msg-{}", i);
            let f = File::open(s)?;
            let msg = BufReader::new(f);

            msgs.push(msg);
        }

        let start = time::precise_time_ns();
        let result = BSscheme::aggregate_verify(pks, msgs, asig)?;
        let end = time::precise_time_ns();

        let time = end - start;

        Ok((result, time))
    };

    let mut cum_sig_aggregate_time = 0;
    let mut cum_agg_verify_time = 0;

    for _ in 0..iterations {
        gen_rand_msg(agg_num)?;

        let (pks, sigs) = profile_setup(agg_num)?;

        let (agg_sig, sig_aggregate_time) = profile_sig_aggregate(pks.clone(), sigs, agg_num)?;

        let (_, agg_verify_time) = profile_agg_verify(pks.clone(), agg_sig, agg_num)?;

        cum_sig_aggregate_time += sig_aggregate_time;
        cum_agg_verify_time += agg_verify_time;
    }

    for i in 0..agg_num {
        let s = format!("msg-{}", i);
        std::fs::remove_file(s)?;
    }

    let average_sig_aggregate_time = cum_sig_aggregate_time / (iterations as u64);
    let average_agg_verify_time = cum_agg_verify_time / (iterations as u64);

    println!("Measuring Bellare-Shoup Signature Aggregation\n");
    println!("Iterations: {}", iterations);
    println!("Message size: {}", msg_size);
    println!("Number of signatures to aggregate: {}\n", agg_num);
    println!("Average aggregation time: {:?} ns", average_sig_aggregate_time);
    println!("Average verification time: {:?} ns\n", average_agg_verify_time);

    Ok(())
}



fn random_vec(n: usize) -> Vec<u8> {
    let mut v = Vec::new();
    for _ in 0..n {
        v.push(rand::random::<u8>());
    }
    v
}
