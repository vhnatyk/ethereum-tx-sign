use ethereum_types::{H160, H256, U256};
use rlp::RlpStream;
use secp256k1::{Message, Secp256k1, SecretKey};

use tiny_keccak::Hasher;
use tiny_keccak::Keccak;

/// Description of a Transaction, pending or in the chain.
#[derive(Debug, Default, Clone, PartialEq, Deserialize, Serialize)]
pub struct RawTransaction {
    /// Nonce
    pub nonce: U256,
    /// Recipient (None when contract creation)
    pub to: Option<H160>,
    /// Transfered value
    pub value: U256,
    /// Gas Price
    #[serde(rename = "gasPrice")]
    pub gas_price: U256,
    /// Gas amount
    pub gas: U256,
    /// Input data
    pub data: Vec<u8>,
}

use std::str::FromStr;

impl RawTransaction {
    /// Convert integer strings into U256
    fn str_to_u256(s: &str) -> U256 {
        U256::from_dec_str(s).unwrap()
    }

    /// Generate new raw Ethereum transaction
    pub fn new(
        nonce: &str,
        gas_price: &str,
        gas: &str,
        to: &str,
        value: &str,
        data: &str,
    ) -> Result<Self, ()> {
        Ok(Self {
            nonce: Self::str_to_u256(nonce),
            gas_price: Self::str_to_u256(gas_price),
            gas: Self::str_to_u256(gas),
            to: Some(H160::from_str(&to.replace("0x", "")).unwrap()),
            value: Self::str_to_u256(value),
            data: data.as_bytes().to_vec(),
        })
    }

    /// Signs and returns the RLP-encoded transaction
    pub fn sign(&self, private_key: &H256, chain_id: &u8) -> Vec<u8> {
        let hash = self.hash(*chain_id);
        let sig = ecdsa_sign(&hash, &private_key.0, &chain_id);
        let mut tx = RlpStream::new();
        tx.begin_unbounded_list();
        self.encode(&mut tx);
        tx.append(&sig.v);
        tx.append(&sig.r);
        tx.append(&sig.s);
        tx.finalize_unbounded_list();
        tx.out()
    }

    /// Threshold signs and returns the transaction
    pub fn mp_ecdsa_sign<FSign>(&self, chain_id: &u8, tss_sign: FSign) -> Vec<u8>
    where
        FSign: Fn(&Vec<u8>) -> Vec<u8>,
    {
        let key_size = secp256k1::constants::SECRET_KEY_SIZE;
        let hash = self.hash(*chain_id);

        let sig_vec = tss_sign(&hash);
        assert_eq!(sig_vec.len(), key_size * 2 + 1);
        let recid = sig_vec[key_size * 2];
        println!("recid: {}", recid);
        let v = vec![recid + chain_id * 2 + 35]; //we receive as (27 + v).. so as per EIP155: (35-27) = 8
        println!("v: {}", v[0]);
        let mut tx = RlpStream::new();
        tx.begin_unbounded_list();
        self.encode(&mut tx);
        tx.append(&v);
        tx.append(&sig_vec.get(0..key_size).unwrap());
        tx.append(&sig_vec.get(key_size..key_size * 2).unwrap());
        tx.finalize_unbounded_list();
        tx.out()
    }

    pub fn hash(&self, chain_id: u8) -> Vec<u8> {
        let mut hash = RlpStream::new();
        hash.begin_unbounded_list();
        self.encode(&mut hash);
        hash.append(&mut vec![chain_id]);
        hash.append(&mut U256::zero());
        hash.append(&mut U256::zero());
        hash.finalize_unbounded_list();
        keccak256_hash(&hash.out())
    }

    fn encode(&self, s: &mut RlpStream) {
        s.append(&self.nonce);
        s.append(&self.gas_price);
        s.append(&self.gas);
        if let Some(ref t) = self.to {
            s.append(t);
        } else {
            s.append(&vec![]);
        }
        s.append(&self.value);
        s.append(&self.data);
    }
}

fn keccak256_hash(bytes: &[u8]) -> Vec<u8> {
    let mut keccak256 = Keccak::v256();
    keccak256.update(bytes);
    let mut output = [0u8; 32];
    keccak256.finalize(&mut output);
    output.to_vec()
}

fn ecdsa_sign(hash: &[u8], private_key: &[u8], chain_id: &u8) -> EcdsaSig {
    let s = Secp256k1::new();
    let msg = Message::from_slice(hash).unwrap();
    let key = SecretKey::from_slice(private_key).unwrap();
    let (v, sig_bytes) = s.sign_recoverable(&msg, &key).serialize_compact();

    EcdsaSig {
        v: vec![v.to_i32() as u8 + chain_id * 2 + 35],
        r: sig_bytes[0..32].to_vec(),
        s: sig_bytes[32..64].to_vec(),
    }
}

pub struct EcdsaSig {
    v: Vec<u8>,
    r: Vec<u8>,
    s: Vec<u8>,
}

#[cfg(test)]
mod test {
    pub struct TestTransaction {
        pub nonce: &'static str,
        pub gas_price: &'static str,
        pub gas: &'static str,
        pub to: &'static str,
        pub value: &'static str,
        pub data: &'static str,
        pub chain_id: u8,
        pub private_key: &'static str,
        pub signed_transaction: &'static str,
        pub transaction_hash: &'static str,
    }

    use super::RawTransaction;
    const ETHEREUM_NETWORK_KOVAN: u8 = 42;
    const ETHEREUM_NETWORK_RINKEBY: u8 = 4;
    const ETHEREUM_NETWORK_ROPSTEN: u8 = 3;
    const ETHEREUM_NETWORK_MAINNET: u8 = 1;

    use ethereum_types::H160;
    use std::str::FromStr;

    const TRANSACTIONS: [TestTransaction; 1] = [
        TestTransaction {
            nonce: "0",
            gas_price: "1000000000",
            gas: "21000",
            to: "0xB5D590A6aBf5E349C1b6C511Bc87CEAbFB3D7e65",
            value: "1000000000000000000",
            data: "",
            chain_id: ETHEREUM_NETWORK_ROPSTEN,
            private_key: "51ce358ffdcf208fadfb01a339f3ab715a89045a093777a44784d9e215277c1c",
            signed_transaction: "0xf86b80843b9aca0082520894b5d590a6abf5e349c1b6c511bc87ceabfb3d7e65880de0b6b3a76400008026a0e19742af3c215eca3b0391ab9edbf3cbad726a18c5209388ebdcccda028197baa034ec566c3d7bf23441873205a7abd6f5c37996a1a3889cdb83ecc20b14f9dcc3",
            transaction_hash: "0x9af5a0a7db1405ffe7de385fbb09d0eb67147f800496f4c185a712f4c374da6e"
        }/*,
        Transaction {
            nonce: "0",
            gas_price: "41000000000",
            gas: "40000",
            to: "0xa554952EEBBC85464F32B7b470F5B7077df4f7e2",
            value: "0",
            data: "Transaction 1",
            chain_id: 3 as u8,
            private_key: "51ce358ffdcf208fadfb01a339f3ab715a89045a093777a44784d9e215277c1c",
            signed_transaction: "0xf8718085098bca5a00829c4094a554952eebbc85464f32b7b470f5b7077df4f7e2808d5472616e73616374696f6e203129a086541fe081eb1a77cb14545fce6d9324c82dab0e1e62dd994662c3f3798ddce9a018be7c3a8aeb32e06d479ec2b17d398239589f3aa6f1896479c12fa8499754a1",
            transaction_hash: "0x145f0d0303ac319911044ff7fb708f23a0a7814c7bcadcec94fb7dbc74f76fff"
        },
        Transaction {
            nonce: "11",
            gas_price: "2000000000",
            gas: "100000",
            to: "0x52C3a8a79a521D10b25569847CB1a3FfB66550D6",
            value: "5000000000000000000",
            data: "Test Data",
            chain_id: 4 as u8,
            private_key: "763459f13c14e02490e71590fe0ebb43cd8758c4adc9fb4bc084b0a798f557e7",
            signed_transaction: "0xf8750b8477359400830186a09452c3a8a79a521d10b25569847cb1a3ffb66550d6884563918244f40000895465737420446174612ba0d2751ac5bc52917575ffb4354fbb9bf0fd339d9eabd3dc5f016b0f695c848afaa014e76c21d60dde6b2452db6bd16d97201ec89ffdfe3c9930646f843220cd99ae",
            transaction_hash: "0x437c266938314b6816014922202efb22a467fa87c8af40ae3d871cadac3de11e"
        },
        Transaction {
            nonce: "12345",
            gas_price: "2000000000",
            gas: "54000",
            to: "0x52C3a8a79a521D10b25569847CB1a3FfB66550D6",
            value: "1000000000000000000000",
            data: "Send 1000 ETH",
            chain_id: 1 as u8,
            private_key: "6cff516706e4eef887c3906f279efa86ac2eeb669b1a2a9f009e85c362fb640c",
            signed_transaction: "0xf87b823039847735940082d2f09452c3a8a79a521d10b25569847cb1a3ffb66550d6893635c9adc5dea000008d53656e6420313030302045544825a0c13bfa13ac09b33ebaf846c9f134633fe03d94b4a3b5b94a6266158740064744a04963f584f3e96c51dc1800b35781e97990771d767766fc5dd5d8913ec2e0858b",
            transaction_hash: "0x862e6475238f7ac42747fcc88373be739b60699563eb80b70a69f11409933761"
        },*/
    ];

    #[test]
    fn test_new_transaction() {
        TRANSACTIONS.iter().for_each(|transaction| {
            let tx = RawTransaction::new(
                transaction.nonce,
                transaction.gas_price,
                transaction.gas,
                transaction.to,
                transaction.value,
                transaction.data,
            )
            .unwrap();

            assert_eq!(format!("{}", tx.nonce), transaction.nonce);
        });
    }

    #[test]
    fn test_signs_transaction_eth() {
        use ethereum_types::*;
        use raw_transaction::RawTransaction;
        use serde_json;
        use std::fs::File;
        use std::io::Read;

        #[derive(Deserialize)]
        struct Signing {
            signed: Vec<u8>,
            private_key: H256,
        }

        let mut file = File::open("./test/test_txs.json").unwrap();
        let mut f_string = String::new();
        file.read_to_string(&mut f_string).unwrap();
        let txs: Vec<(RawTransaction, Signing)> = serde_json::from_str(&f_string).unwrap();
        let chain_id = 0;
        for (tx, signed) in txs.into_iter() {
            assert_eq!(signed.signed, tx.sign(&signed.private_key, &chain_id));
        }
    }

    #[test]
    fn test_signs_transaction_ropsten() {
        use ethereum_types::*;
        use raw_transaction::RawTransaction;
        use serde_json;
        use std::fs::File;
        use std::io::Read;

        #[derive(Deserialize)]
        struct Signing {
            signed: Vec<u8>,
            private_key: H256,
        }

        let mut file = File::open("./test/test_txs_ropsten.json").unwrap();
        let mut f_string = String::new();
        file.read_to_string(&mut f_string).unwrap();
        let txs: Vec<(RawTransaction, Signing)> = serde_json::from_str(&f_string).unwrap();
        let chain_id = 3;
        let mut fmt: String;
        for (tx, signed) in txs.into_iter() {
            assert_eq!(signed.signed, tx.sign(&signed.private_key, &chain_id));
            fmt = format!(
                "tx to: {} | tx hash: {} | signed tx: {}",
                tx.to.unwrap_or(H160::zero()),
                hex::encode(tx.hash(chain_id)),
                hex::encode(signed.signed)
            )
            .to_owned();
            println!("{}", &fmt);
        }
        // assert!(false);
    }
}
