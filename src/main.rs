use clap::Parser;

use sp_core::{
	crypto::{
		unwrap_or_default_ss58_version, ExposeSecret, SecretString, Ss58AddressFormat, Ss58Codec,
		Zeroize,
	},
	hexdisplay::HexDisplay,
    ed25519::{Pair, Public},
    Pair as _,
};
use std::{fmt::Write, num::ParseIntError};


#[derive(clap::Parser)]
struct Cli {
    #[command(subcommand)]
    action: Action,
}

#[derive(Debug, clap::Subcommand)]
enum Action {
    Encrypt {
        #[arg(long)]
        key: String,

        data: String,
    },
    Decrypt {
        #[arg(long)]
        key: String,

        data: String,
    }
}

#[derive(parity_scale_codec::Encode, parity_scale_codec::Decode)]
struct EncodedData {
    magic: [u8; 4],
    public: [u8; 32],
    cipher_text: Vec<u8>,
}

impl EncodedData {
    fn encode(plain_data: Vec<u8>, public: Public) -> Self {
        let mut csprng = rand::thread_rng();

        let raw_public = AsRef::<[u8;32]>::as_ref(&public).clone();
        let ecies_public_key = ecies_ed25519::PublicKey::from_bytes(&raw_public[..]).expect("Should be valid public key representation");

        let cipher_text = ecies_ed25519::encrypt(&ecies_public_key, plain_data.as_ref(), &mut csprng).expect("Failed to encrypt");

        EncodedData {
            magic: b"sfex".clone(),
            public: raw_public,
            cipher_text,
        }
    }

    fn decode(self, pair: Pair) -> String {
        assert_eq!(&self.magic, b"sfex");

        let mut raw_secret = [0u8; 32];
        raw_secret[..].copy_from_slice(&pair.to_raw_vec()[..]);

        let ecies_secret_key = ecies_ed25519::SecretKey::from_bytes(&raw_secret[..]).expect("Should be valid secret key representation");

        let plain_data = ecies_ed25519::decrypt(&ecies_secret_key, self.cipher_text.as_ref()).expect("Failed to decrypt");

        String::from_utf8(plain_data).expect("Non-utf8 in text")
    }
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

pub fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

fn main() {
    let cli = Cli::parse();
    match cli.action {
        Action::Encrypt { key, data } => {
            let plain_data = data.as_bytes().to_vec();
            let public = Public::from_ss58check(&key).unwrap();

            let encoded_data = EncodedData::encode(plain_data, public);

            let encoded = parity_scale_codec::Encode::encode(&encoded_data);

            println!("{}", encode_hex(encoded.as_ref()));
        },

        Action::Decrypt { key, data} => {
            let pair = Pair::from_string(&key, None).expect("Failed to read key");
            let encoded_data: EncodedData = parity_scale_codec::Decode::decode(&mut &decode_hex(&data).expect("Failed to decode hex")[..])
                .expect("Failed to decode encoded data");

            let plain_data = encoded_data.decode(pair);

            println!("{}", plain_data);
        }
    }

 }
