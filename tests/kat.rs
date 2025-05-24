use qrypto::{
    kem::kyber::{Kyber1024, Kyber512, Kyber768, KyberKeyPair},
    traits::KEM,
};
use std::path::Path;

mod kat_parser;
mod test_rng;
use kat_parser::{parse_kat_rsp_file, KatTestCase};
use test_rng::TestRng;

fn run_kat_test<A: KEM<PublicKey = Vec<u8>, SecretKey = Vec<u8>, KeyPair = KyberKeyPair>>(
    test_case: KatTestCase,
    kat_file: &str,
) -> Result<(), String> {
    println!("Running KAT test {} from {}", test_case.count, kat_file);

    // Generate keypair with seed
    let keypair = A::generate_keypair_with_seed(&test_case.seed).map_err(|e| format!("Keypair generation failed: {}", e))?;

    // Verify public and secret keys
    if keypair.public_key() != &test_case.pk {
        println!("Public key mismatch for test {}: expected {:x?} \n\ngot: {:x?}", test_case.count, test_case.pk, keypair.public_key());
        return Err(format!("Public key mismatch for test {}", test_case.count));
    }
    if keypair.secret_key() != &test_case.sk {
        println!("Secret key mismatch for test {}: expected {:x?}, got {:x?}", test_case.count, test_case.sk, keypair.secret_key());
        return Err(format!("Secret key mismatch for test {}", test_case.count));
    }

    // Encapsulate with seeded RNG
    let mut rng = TestRng::new(&test_case.seed);
    let (ciphertext, shared_secret_bob) = A::encapsulate_with_rng(&test_case.pk, &mut rng).map_err(|e| format!("Encapsulation failed: {}", e))?;

    // Verify ciphertext and shared secret
    if ciphertext != test_case.ct {
        println!("Ciphertext mismatch for test {}: expected {:x?}, got {:x?}", test_case.count, test_case.ct, ciphertext);
        return Err(format!("Ciphertext mismatch for test {}", test_case.count));
    }
    if shared_secret_bob != test_case.ss {
        println!("Shared secret (enc) mismatch for test {}: expected {:x?}, got {:x?}", test_case.count, test_case.ss, shared_secret_bob);
        return Err(format!("Shared secret (enc) mismatch for test {}", test_case.count));
    }

    // Decapsulate and verify shared secret
    let shared_secret_alice = A::decapsulate(&test_case.sk, &test_case.ct).map_err(|e| format!("Decapsulation failed: {}", e))?;

    if shared_secret_alice != test_case.ss {
        println!("Shared secret (dec) mismatch for test {}: expected {:x?}, got {:x?}", test_case.count, test_case.ss, shared_secret_alice);
        return Err(format!("Shared secret (dec) mismatch for test {}", test_case.count));
    }

    println!("KAT test {} passed", test_case.count);
    Ok(())
}

#[test]
fn kat_kyber512() {
    let kat_file = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/kat/kyber512/PQCkemKAT_1632.rsp");
    let test_cases = parse_kat_rsp_file(kat_file.to_str().expect("Invalid path")).expect("Failed to parse KAT file");

    for test_case in test_cases {
        run_kat_test::<Kyber512>(test_case, kat_file.to_str().expect("Invalid path")).expect("KAT test failed");
    }
}

#[test]
fn kat_kyber768() {
    let kat_file = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/kat/kyber768/PQCkemKAT_2400.rsp");
    let test_cases = parse_kat_rsp_file(kat_file.to_str().expect("Invalid path")).expect("Failed to parse KAT file");

    for test_case in test_cases {
        run_kat_test::<Kyber768>(test_case, kat_file.to_str().expect("Invalid path")).expect("KAT test failed");
    }
}

#[test]
fn kat_kyber1024() {
    let kat_file = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/kat/kyber1024/PQCkemKAT_3168.rsp");
    let test_cases = parse_kat_rsp_file(kat_file.to_str().expect("Invalid path")).expect("Failed to parse KAT file");

    for test_case in test_cases {
        run_kat_test::<Kyber1024>(test_case, kat_file.to_str().expect("Invalid path")).expect("KAT test failed");
    }
}
