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
fn alice_repro() {
    let scalar = hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a").unwrap();
    let mut k = [0u8; 32];
    k.copy_from_slice(&scalar);
    let base = [9u8; 32];
    let result = X25519::diffie_hellman(&k, &base);
    println!("kat-style diffie_hellman = {}", hex::encode(&result));

    let u = [9u8; 32];
    let r2 = X25519::diffie_hellman(&k, &u);
    println!("u=[9;32] diffie_hellman  = {}", hex::encode(&r2));
}
