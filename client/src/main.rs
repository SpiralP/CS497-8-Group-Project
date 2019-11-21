use openssl::bn::BigNumContext;
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey, PointConversionForm};
use openssl::ecdsa::EcdsaSig;
use openssl::error::ErrorStack;
use openssl::hash::hash;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::*;
use openssl::rand::rand_bytes;
use openssl::sign::{Signer, Verifier};
use openssl::symm::Cipher;
use openssl::symm::Crypter;
use openssl::symm::Mode;

type Result<T> = std::result::Result<T, ErrorStack>;

fn main() -> Result<()> {
    let private_key = generate_private_key()?;

    let pkey = PKey::from_ec_key(private_key)?;

    // sign
    let signer = Signer::new(MessageDigest::sha256(), &pkey)?;
    let signature = signer.sign_oneshot_to_vec(b"hello")?;

    println!("signature: {:?}", signature);

    // verify
    let verifier = Verifier::new(MessageDigest::sha256(), &pkey)?;
    let verified = verifier.verify_oneshot(&signature, b"hello")?;

    // println!("{:?}", verified);

    // let mut ctx = BigNumContext::new()?;
    // let key = pkey.ec_key()?.public_key().to_bytes(
    //     &group,
    //     PointConversionForm::UNCOMPRESSED,
    //     &mut ctx,
    // )?;
    // let encrypted = encrypt(Cipher::aes_128_gcm(), &key, None, b"hello")?;

    // println!("{:?}", encrypted);

    Ok(())
}

fn get_curve() -> Result<EcGroup> {
    Ok(EcGroup::from_curve_name(Nid::SECP256K1)?)
}

fn get_cipher() -> Result<Cipher> {
    Ok(Cipher::aes_128_ctr())
}

fn generate_private_key() -> Result<EcKey<Private>> {
    let group = get_curve()?;
    Ok(EcKey::generate(&group)?)
}

fn get_public_key(private_key: &EcKey<Private>) -> Result<EcKey<Public>> {
    let group = get_curve()?;
    let public_key_point = private_key.public_key();
    Ok(EcKey::from_public_key(&group, public_key_point)?)
}

fn get_shared_secret(
    my_private_key: &PKey<Private>,
    their_public_key: &PKey<Public>,
) -> Result<Vec<u8>> {
    let mut deriver = Deriver::new(my_private_key)?;
    deriver.set_peer(their_public_key)?;
    let key = deriver.derive_to_vec()?;

    let key_hash = hash(MessageDigest::sha256(), &key)?;
    let mut key_hash = key_hash.to_vec();
    key_hash.truncate(16); // take first 16 chars

    assert_eq!(key_hash.len(), 16); // needs to be 128 bits for aes-128

    Ok(key_hash)
}

#[test]
fn test_signing() -> Result<()> {
    let my_private_key = generate_private_key()?;
    let my_public_key = get_public_key(&my_private_key)?;

    let data = b"hello";

    // signing
    let der_signature = {
        let data_hash = hash(MessageDigest::sha256(), data)?;
        EcdsaSig::sign(&data_hash, &my_private_key)?.to_der()?
    };

    println!("signature: {:?}", der_signature);

    // verifying
    {
        let data_hash = hash(MessageDigest::sha256(), data)?;

        let ecdsa = EcdsaSig::from_der(&der_signature)?;
        assert!(ecdsa.verify(&data_hash, &my_public_key)?);
    }

    Ok(())
}

fn encrypt(key: &[u8], data: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let cipher = get_cipher()?;

    let mut c = Crypter::new(cipher, Mode::Encrypt, key, Some(iv))?;
    let mut out = vec![0; data.len() + cipher.block_size()];
    let count = c.update(data, &mut out)?;
    let rest = c.finalize(&mut out[count..])?;
    out.truncate(count + rest);

    Ok(out)
}

fn decrypt(key: &[u8], data: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let cipher = get_cipher()?;

    let mut c = Crypter::new(cipher, Mode::Decrypt, key, Some(&iv))?;
    let mut out = vec![0; data.len() + cipher.block_size()];
    let count = c.update(data, &mut out)?;
    let rest = c.finalize(&mut out[count..])?;
    out.truncate(count + rest);
    Ok(out)
}

fn get_iv() -> Result<Vec<u8>> {
    // Initialization Vector
    // this is a temporary random number
    // it's OK to make public
    // it must be unique and random, never use the same twice
    let iv_len = get_cipher()?.iv_len().unwrap(); // 96 bits
    let mut iv = vec![0; iv_len];
    rand_bytes(&mut iv)?;

    Ok(iv)
}

#[test]
fn test_encryption() -> Result<()> {
    let my_private_key = generate_private_key()?;
    let their_public_key = get_public_key(&generate_private_key()?)?;

    let shared_secret = get_shared_secret(
        &PKey::from_ec_key(my_private_key)?,
        &PKey::from_ec_key(their_public_key)?,
    )?;

    println!("shared secret len {}", shared_secret.len());

    let iv = get_iv()?;

    let encrypted = encrypt(&shared_secret, b"hello", &iv)?;

    println!("encrypted: {:?}", encrypted);

    let decrypted = decrypt(&shared_secret, &encrypted, &iv)?;

    println!("decrypted: {:?}", String::from_utf8_lossy(&decrypted));

    Ok(())
}

// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256

// https://ciphersuite.info/cs/TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256/

// Protocol:
// Transport Layer Security (TLS)

// Key Exchange:
// Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)

// Authentication:
// Elliptic Curve Digital Signature Algorithm (ECDSA)

// Encryption:
// Advanced Encryption Standard with 128bit key in Galois/Counter mode (AES 128 GCM)

// Hash:
// Secure Hash Algorithm 256 (SHA256)
