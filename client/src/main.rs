use byteorder::{BigEndian, ByteOrder, NetworkEndian};
use openssl::{
  bn::BigNumContext,
  derive::Deriver,
  ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
  ecdsa::EcdsaSig,
  error::ErrorStack,
  hash::{hash, MessageDigest},
  nid::Nid,
  pkey::*,
  rand::rand_bytes,
  sign::{Signer, Verifier},
  symm::{Cipher, Crypter, Mode},
};
use std::{
  io::{Read, Write},
  net::{TcpStream, ToSocketAddrs},
};

type Result<T> = std::result::Result<T, ErrorStack>;

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

fn get_public_key(private_key: &EcKey<Private>) -> Result<PKey<Public>> {
  let group = get_curve()?;
  let public_key_point = private_key.public_key();
  Ok(PKey::from_ec_key(EcKey::from_public_key(
    &group,
    public_key_point,
  )?)?)
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
  key_hash.truncate(16); // take first 16 bytes

  assert_eq!(key_hash.len(), 16); // needs to be 128 bits for aes-128

  Ok(key_hash)
}

// #[test]
// fn test_signing() -> Result<()> {
//   let my_private_key = generate_private_key()?;
//   let my_public_key = get_public_key(&my_private_key)?;

//   let data = b"hello";

//   // signing
//   let der_signature = {
//     let data_hash = hash(MessageDigest::sha256(), data)?;
//     EcdsaSig::sign(&data_hash, &my_private_key)?.to_der()?
//   };

//   println!("signature: {:?}", der_signature);

//   // verifying
//   {
//     let data_hash = hash(MessageDigest::sha256(), data)?;

//     let ecdsa = EcdsaSig::from_der(&der_signature)?;
//     assert!(ecdsa.verify(&data_hash, &my_public_key)?);
//   }

//   Ok(())
// }

fn encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
  let cipher = get_cipher()?;

  let mut iv = get_iv()?;
  let mut c = Crypter::new(cipher, Mode::Encrypt, key, Some(&iv))?;
  let mut out = vec![0; data.len() + cipher.block_size()];
  let count = c.update(data, &mut out)?;
  let rest = c.finalize(&mut out[count..])?;
  out.truncate(count + rest);

  let mut concat_bytes = Vec::new();
  concat_bytes.append(&mut iv);
  concat_bytes.append(&mut out);

  Ok(concat_bytes)
}

fn decrypt(key: &[u8], data_with_iv: &[u8]) -> Result<Vec<u8>> {
  let cipher = get_cipher()?;

  let iv = &data_with_iv[0..16];
  let data = &data_with_iv[16..];

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
  let iv_len = get_cipher()?.iv_len().unwrap(); // 96 bits????
  let mut iv = vec![0; iv_len];
  rand_bytes(&mut iv)?;

  Ok(iv)
}

// #[test]
// fn test_encryption() -> Result<()> {
//   let my_private_key = generate_private_key()?;
//   let their_public_key = get_public_key(&generate_private_key()?)?;

//   let shared_secret = get_shared_secret(
//     &PKey::from_ec_key(my_private_key)?,
//     &PKey::from_ec_key(their_public_key)?,
//   )?;

//   println!("shared secret len {}", shared_secret.len());

//   let encrypted = encrypt(&shared_secret, b"hello")?;

//   println!("encrypted: {:?}", encrypted);

//   let decrypted = decrypt(&shared_secret, &encrypted)?;

//   println!("decrypted: {:?}", String::from_utf8_lossy(&decrypted));

//   Ok(())
// }

fn public_key_to_bytes<T: HasPublic>(key: &PKey<T>) -> Vec<u8> {
  let mut ctx = BigNumContext::new().unwrap();
  key
    .ec_key()
    .unwrap()
    .public_key()
    .to_bytes(
      &get_curve().unwrap(),
      PointConversionForm::UNCOMPRESSED,
      &mut ctx,
    )
    .unwrap()
}

fn public_key_from_bytes(bytes: &[u8]) -> PKey<Public> {
  let mut ctx = BigNumContext::new().unwrap();

  let group = get_curve().unwrap();

  let point = EcPoint::from_bytes(&group, bytes, &mut ctx).unwrap();

  PKey::from_ec_key(EcKey::from_public_key(&group, &point).unwrap()).unwrap()
}

struct Client {
  socket: TcpStream,
  my_private_key: PKey<Private>,
  my_public_key: PKey<Public>,
  shared_secret: Option<Vec<u8>>,
}

impl Client {
  pub fn connect<A: ToSocketAddrs>(addr: A, my_private_key: EcKey<Private>) -> Self {
    let socket = TcpStream::connect(addr).unwrap();

    let my_public_key = get_public_key(&my_private_key).unwrap();
    let my_private_key = PKey::from_ec_key(my_private_key).unwrap();

    let mut client = Client {
      socket,
      my_private_key,
      my_public_key,
      shared_secret: None,
    };

    println!("do_handshake");
    client.do_handshake();
    println!("do_handshake done");

    client
  }

  fn do_handshake(&mut self) {
    let my_public_key_bytes = public_key_to_bytes(&self.my_public_key);
    self.write_chunk(&my_public_key_bytes).unwrap();

    let their_public_key_bytes = self.read_chunk().unwrap();
    let their_public_key = public_key_from_bytes(&their_public_key_bytes);

    let shared_secret = get_shared_secret(&self.my_private_key, &their_public_key).unwrap();
    self.shared_secret = Some(shared_secret);
  }

  fn write_chunk(&mut self, data: &[u8]) -> Result<()> {
    let mut buf = [0; 2];
    NetworkEndian::write_u16(&mut buf, data.len() as u16);
    self.socket.write_all(&buf).unwrap();
    self.socket.write_all(&data).unwrap();
    Ok(())
  }

  fn read_chunk(&mut self) -> Result<Vec<u8>> {
    let mut buf = [0; 2];
    self.socket.read_exact(&mut buf).unwrap();
    let data_len = NetworkEndian::read_u16(&buf);

    let mut data_buf = vec![0; data_len as usize];
    self.socket.read_exact(&mut data_buf).unwrap();
    Ok(data_buf)
  }

  pub fn send_message(&mut self, data: &[u8]) {
    let encrypted_data = encrypt(self.shared_secret.as_ref().unwrap(), data).unwrap();

    self.write_chunk(&encrypted_data).unwrap();
  }

  pub fn start_receive_loop(&mut self) {
    self.send_message(b"hellasjdfklajsdklfo!");

    loop {
      let encrypted_data = self.read_chunk().unwrap();

      let data = decrypt(self.shared_secret.as_ref().unwrap(), &encrypted_data).unwrap();

      self.handle_message(data);
    }
  }

  fn handle_message(&mut self, data: Vec<u8>) {
    println!("message: {:?}", data);
  }
}

fn private_key_from_bytes(private_key: Vec<u8>, public_key: Vec<u8>) -> EcKey<private> {
  let mut ctx = BigNumContext::new().unwrap();

  let group = get_curve().unwrap();

  let point = EcPoint::from_bytes(&group, bytes, &mut ctx).unwrap();
  
  let big_number = BigNum::from_slice(&data);

  EcKey::from_private_componenets(&group, &big_number, &point).unwrap()
}

fn main() -> Result<()> {
  // load our private key
  let private_key = private_key_from_bytes(fs::read("client").unwrap(), fs::read("client.pub").unwrap());
  // let pkey = PKey::from_ec_key(private_key)?;

  let mut client = Client::connect("127.0.0.1:12345", private_key);
  client.start_receive_loop();

  // // sign
  // let signer = Signer::new(MessageDigest::sha256(), &pkey)?;
  // let signature = signer.sign_oneshot_to_vec(b"hello")?;

  // println!("signature: {:?}", signature);

  // // verify
  // let verifier = Verifier::new(MessageDigest::sha256(), &pkey)?;
  // let verified = verifier.verify_oneshot(&signature, b"hello")?;

  // println!("{:?}", verified);

  //   let mut ctx = BigNumContext::new()?;
  //   let key = pkey.ec_key()?.public_key().to_bytes(
  //       &group,
  //       PointConversionForm::UNCOMPRESSED,
  //       &mut ctx,
  //   )?;
  // let encrypted = encrypt(Cipher::aes_128_gcm(), &key, None, b"hello")?;

  // println!("{:?}", encrypted);

  Ok(())
}

// #[test]
// fn test_connection() {
//   let mut stream = TcpStream::connect("127.0.0.1:12345").unwrap();

//   println!("connected, writing");
//   write_chunk(&mut stream, b"hello").unwrap();

//   println!("got {:#?}", read_chunk(&mut stream).unwrap());

//   std::thread::sleep_ms(1000);

//   write_chunk(&mut stream, b"hahhahaha").unwrap();

//   std::thread::sleep_ms(10000);
// }

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
