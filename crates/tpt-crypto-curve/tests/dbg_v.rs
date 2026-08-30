use tpt_crypto_curve::X25519;
#[test]
fn dbg_vec2_alice() {
    let k = hex::decode("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d").unwrap();
    let u = hex::decode("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493").unwrap();
    let mut kb=[0u8;32]; kb.copy_from_slice(&k); let mut ub=[0u8;32]; ub.copy_from_slice(&u);
    eprintln!("LIB vec2 = {:02x?}", X25519::diffie_hellman(&kb,&ub));
    let ka = hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a").unwrap();
    let mut kab=[0u8;32]; kab.copy_from_slice(&ka); let ua=[9u8;32];
    eprintln!("LIB alice= {:02x?}", X25519::diffie_hellman(&kab,&ua));
}
mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
        let b=s.as_bytes(); let mut o=Vec::with_capacity(b.len()/2); let mut i=0;
        while i<b.len(){ o.push(((b[i] as char).to_digit(16).ok_or(())?*16+(b[i+1] as char).to_digit(16).ok_or(())?) as u8); i+=2; }
        Ok(o)
    }
}
