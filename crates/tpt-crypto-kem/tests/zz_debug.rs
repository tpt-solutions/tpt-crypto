use tpt_crypto_hash::sha3::Sha3_512;
use tpt_crypto_hash::Hasher;
use tpt_crypto_kem::ml_kem::{keygen_seed, MlKem512};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn arr32(v: &[u8]) -> [u8; 32] {
    v.try_into().unwrap()
}

#[test]
fn debug_pk() {
    let text = std::fs::read_to_string(format!(
        "{}/tests/kat/fips203_512.rsp",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    // Slice only up to the second "count = " so we stay in the count=0 block.
    let lines: Vec<&str> = text.lines().collect();
    let mut end = lines.len();
    for (i, l) in lines.iter().enumerate().skip(1) {
        if l.trim().starts_with("count =") {
            end = i;
            break;
        }
    }
    let mut d: Vec<u8> = Vec::new();
    let mut z: Vec<u8> = Vec::new();
    let mut pk: Vec<u8> = Vec::new();
    let mut sk: Vec<u8> = Vec::new();
    for l in &lines[..end] {
        if let Some((k, v)) = l.split_once('=') {
            match k.trim() {
                "d" => d = hex::decode(v.trim()).unwrap(),
                "z" => z = hex::decode(v.trim()).unwrap(),
                "pk" => pk = hex::decode(v.trim()).unwrap(),
                "sk" => sk = hex::decode(v.trim()).unwrap(),
                _ => {}
            }
        }
    }
    let dr: [u8; 32] = arr32(&d);
    let zr: [u8; 32] = arr32(&z);
    let (ek, dk) = keygen_seed::<MlKem512>(&dr, &zr);

    println!("vector d = {}", hex(&d));
    println!("vector z = {}", hex(&z));
    println!("vector pk[0..8]  = {}", hex(&pk[0..8]));
    println!("our pk[0..8]     = {}", hex(&ek.bytes[0..8]));
    println!("vector pk last8  = {}", hex(&pk[pk.len() - 8..]));
    println!("our pk last8     = {}", hex(&ek.bytes[ek.bytes.len() - 8..]));

    let mut h = Sha3_512::new();
    h.update(&d);
    h.update(&[0x02u8]);
    let g = h.finalize();
    println!("G(d||2)[0..8]    = {}", hex(&g[..8]));
    println!("G(d||2)[32..40]  = {}", hex(&g[32..40]));

    println!("vector pk starts with G-rho: {}", pk[0..32] == g[..32]);
    println!("vector pk ends   with G-rho: {}", pk[pk.len() - 32..] == g[..32]);
    println!("our pk starts with G-rho: {}", ek.bytes[0..32] == g[..32]);

    println!("vector pk len = {}, our pk len = {}", pk.len(), ek.bytes.len());
    println!("vector sk len = {}, our sk len = {}", sk.len(), dk.bytes.len());
    println!("vector sk[0..8]  = {}", hex(&sk[0..8]));
    println!("vector sk last8  = {}", hex(&sk[sk.len() - 8..]));
    println!("our sk[0..8]  = {}", hex(&dk.bytes[0..8]));
    println!("our sk last8  = {}", hex(&dk.bytes[dk.bytes.len() - 8..]));
    println!("vector sk contains vector pk: {}", sk.windows(pk.len()).any(|w| w == pk.as_slice()));
    println!("vector sk contains G-rho: {}", sk.windows(32).any(|w| w == &g[..32]));
    println!("our sk contains our pk: {}", dk.bytes.windows(ek.bytes.len()).any(|w| w == ek.bytes));
    // count how many vector bytes equal ours up front
    let m = pk.iter().zip(ek.bytes.iter()).filter(|(a, b)| a == b).count();
    println!("vector pk vs our pk equal bytes: {m}/{}", ek.bytes.len());
}