extern crate bs_agg_ots;

fn main() {
    bs_agg_ots::profile::profile_run_all(100, 32, 16).expect("Profile failed");
}

