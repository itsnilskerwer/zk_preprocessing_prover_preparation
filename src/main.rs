use std::fs::{self, File};
use std::io::Write;
use std::str::FromStr;
use ark_ff::{PrimeField, BigInteger};
use ark_bn254::Fr;
use k256::ecdsa::{Signature, VerifyingKey};
use k256::ecdsa::signature::Verifier;
use k256::Scalar;
use k256::ecdsa::signature::hazmat::PrehashVerifier;

// load verifying key from file
fn load_verifying_key(path: &str) -> VerifyingKey {
    let bytes_vk = fs::read(path).expect("failed to read pubkey");
    VerifyingKey::from_sec1_bytes(&bytes_vk).expect("invalid SEC1 key")
}

// load signature as bytes from file
fn load_signature(path: &str) -> [u8; 64] {
    let bytes = fs::read(path).expect("failed to read signature");
    assert!(
        bytes.len() == 64,
        "Expected 64-byte raw ECDSA signature, got {}",
        bytes.len()
    );

    let mut sig = [0u8; 64];
    sig.copy_from_slice(&bytes);
    sig
}


/// Convert a field element to 0x-prefixed hex
fn field_to_hex<F: PrimeField>(f: &F) -> String {
    let bytes = f.into_bigint().to_bytes_be();
    format!("0x{}", hex::encode(bytes))
}

fn signature_from_rs(signature: [u8; 64]) -> Signature {
    Signature::from_slice(&signature)
        .expect("invalid raw ECDSA signature")
}

// --- Warning: Unused -------------------
fn ecdsa_signature_rs(sig: &k256::ecdsa::Signature) -> [u8; 64] {
    let r = sig.r().to_bytes();
    let s = sig.s().to_bytes();

    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&r);
    out[32..].copy_from_slice(&s);

    out
    /* 
    // for returning hex strings (useful for smart-contract implementations)
    (
        format!("0x{}", hex::encode(r)),
        format!("0x{}", hex::encode(s)),
    ) */
}
/// -----------------------------------------------

fn verifying_key_xy(vk: &k256::ecdsa::VerifyingKey) -> ([u8; 32], [u8; 32]) {
    let point = vk.to_encoded_point(false);
    let x = point.x().expect("missing x");
    let y = point.y().expect("missing y");

    let mut x_arr = [0u8; 32];
    let mut y_arr = [0u8; 32];

    x_arr.copy_from_slice(x);
    y_arr.copy_from_slice(y);

    (x_arr, y_arr)

    /* 
    // for returning hex strings
    (
        format!("0x{}", hex::encode(x)),
        format!("0x{}", hex::encode(y)),
    ) */
}

fn fr_to_32be_bytes(f: &Fr) -> [u8; 32] {
    let bigint = f.into_bigint();
    let bytes = bigint.to_bytes_be();

    let mut out = [0u8; 32];
    let start = 32 - bytes.len();
    out[start..].copy_from_slice(&bytes);
    out
}

fn main() {
    println!("Hello, prover_preparation!");

    let merkle_root = ark_bn254::Fr::from_str(
        "12962407178973411323556031498218835147452685534794775607614173838598524125905"
    ).unwrap();    

    let verifying_key = load_verifying_key("../merkle_poseidon_root_ecdsa/verifying_key.sec1");

    let signature = load_signature("../merkle_poseidon_root_ecdsa/signature.sig");

    let leaves: [Fr; 4] = [
        Fr::from_str("4910744290370992967594783267190021468504474627849903460949550480278838140199").unwrap(),
        Fr::from_str("10194548762545774750915906808733983907201990848957491253134558847853880061861").unwrap(),
        Fr::from_str("8361791287903088380138808503792110151023699568954984532145283304862179688869").unwrap(),
        Fr::from_str("2902104138811596866383925023591303991501113627166467298658710052247721224774").unwrap(),
    ];

    // ----- verify signature -----
    // First, convert signature bytes back to a ECDSA Signature
    let sig = signature_from_rs(signature);

    // Second, turn root Field back into bytes
    let root_bytes = fr_to_32be_bytes(&merkle_root);
    println!("VERIFY root bytes: {:02x?}", root_bytes);

    println!("Trying to verify merkle root with newly created signature...");
    // Regular verify() function will fail because of internal hashing of the message
    // assert!(verifying_key.verify(&root_bytes, &sig).is_ok());
    // So, we need to enfore no hashing of the message
    assert!(
        verifying_key
            .verify_prehash(&root_bytes, &sig)
            .is_ok()
    ); // this passes

    // ------ write Prover.toml file (Noir inputs) ------

    write_prover_toml(
        "../../merkle_poseidon_root_ecdsa_test/Prover.toml",
        &leaves.try_into().unwrap(),
        &merkle_root,
        &verifying_key,
        &signature,
    ).expect("Failed to write Prover.toml");

    println!("Prover.toml written successfully");
}

fn bytes_to_toml_array(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("0x{:02x}", b))
        .collect::<Vec<_>>()
        .join(", ")
}

fn write_prover_toml(
    path: &str,
    // leaves: &[ark_bn254::Fr; 4],
    // root: &ark_bn254::Fr,
    // vk: &k256::ecdsa::VerifyingKey,
    // sig: &k256::ecdsa::Signature,
    leaves: &[Fr; 4],
    root: &Fr,
    vk: &VerifyingKey,
    // sig: &Signature,
    signature_rs: &[u8; 64],

) -> std::io::Result<()> {

    let mut file = File::create(path)?;

    let root_hex = field_to_hex(root); // convert
    let (pk_x, pk_y) = verifying_key_xy(vk);

    writeln!(file, "root = \"{}\"", root_hex)?;

    // writeln!(file, "pub_key_x = \"{}\"", pk_x)?; // hex
    // writeln!(file, "pub_key_y = \"{}\"", pk_y)?; // hex
    writeln!(file, "pub_key_x = [{}]", bytes_to_toml_array(&pk_x))?;
    writeln!(file, "pub_key_y = [{}]", bytes_to_toml_array(&pk_y))?;

    // writeln!(file, "signature = [\"{}\", \"{}\"]", sig_r, sig_s)?; // hex
    writeln!(file, "signature = [{}]", bytes_to_toml_array(signature_rs))?;


    writeln!(
        file,
        "leaves = [{}]",
        leaves
            .iter()
            .map(|f| format!("\"{}\"", field_to_hex(f)))
            .collect::<Vec<_>>()
            .join(", ")
    )?;

    Ok(())
}
