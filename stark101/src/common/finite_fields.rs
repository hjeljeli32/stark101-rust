use ark_ff::fields::{Fp64, MontBackend, MontConfig};

#[derive(MontConfig)]
#[modulus = "3221225473"]
#[generator = "5"]
pub struct MyFieldConfig;
pub type MyField = Fp64<MontBackend<MyFieldConfig, 1>>;
