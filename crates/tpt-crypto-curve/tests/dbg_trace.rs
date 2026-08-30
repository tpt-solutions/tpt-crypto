use tpt_crypto_curve::X25519;

mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
        let mut out = Vec::with_capacity(s.len() / 2);
        let b = s.as_bytes();
        let mut i = 0;
        while i < b.len() {
            let hi = (b[i] as char).to_digit(16).ok_or(())?;
            let lo = (b[i + 1] as char).to_digit(16).ok_or(())?;
            out.push((hi * 16 + lo) as u8);
            i += 2;
        }
        Ok(out)
    }
    pub fn encode(b: &[u8]) -> String {
        let mut s = String::with_capacity(b.len() * 2);
        for x in b {
            s.push_str(&format!("{:02x}", x));
        }
        s
    }
}

#[test]
fn dump_final() {
    let k = hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a").unwrap();
    let u = hex::decode("0900000000000000000000000000000000000000000000000000000000000000").unwrap();
    let k: [u8; 32] = k.try_into().unwrap();
    let u: [u8; 32] = u.try_into().unwrap();
    let (swap, pre_x2, pre_z2, pre_x3, pre_z3, post_x2, post_z2, res) = X25519::dbg_final(&k, &u);
    let dh = X25519::diffie_hellman(&k, &u);
    println!("diffie_hellman = {}", hex::encode(&dh));
    println!(
        "swap={} pre_x2={} pre_z2={} pre_x3={} pre_z3={} post_x2={} post_z2={} res={}",
        swap as u8,
        hex::encode(&pre_x2),
        hex::encode(&pre_z2),
        hex::encode(&pre_x3),
        hex::encode(&pre_z3),
        hex::encode(&post_x2),
        hex::encode(&post_z2),
        hex::encode(&res),
    );
}
