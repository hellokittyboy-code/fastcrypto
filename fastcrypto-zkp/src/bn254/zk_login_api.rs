// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;
use std::string::ToString;
use ark_snark::SNARK;
use fastcrypto::rsa::{Base64UrlUnpadded, Encoding};

use super::zk_login::{JwkId, ZkLoginInputs, JWK, fetch_jwk_from_salt_service};
use crate::bn254::utils::{gen_address_seed_with_salt_hash, get_zk_login_address};
use crate::zk_login_utils::{
    g1_affine_from_str_projective, g2_affine_from_str_projective, Bn254FqElement, Bn254FrElement,
};
pub use ark_bn254::{Bn254, Fr as Bn254Fr};
pub use ark_ff::ToConstraintField;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, VerifyingKey};
pub use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use im::hashmap::HashMap as ImHashMap;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

/// Enum to specify the environment to use for verifying keys.
#[derive(Serialize, Clone, Deserialize, Debug, Eq, PartialEq, Copy)]
pub enum ZkLoginEnv {
    /// Use the secure global verifying key derived from ceremony.
    Prod,
    /// Use the insecure global verifying key.
    Test,
}

impl Default for ZkLoginEnv {
    fn default() -> Self {
        Self::Prod
    }
}

/// Corresponding to proofs generated from prover (prod). Produced from ceremony. Secure to use for mainnet.
static GLOBAL_VERIFYING_KEY: Lazy<PreparedVerifyingKey<Bn254>> = Lazy::new(global_pvk);

/// Corresponding to proofs generated from prover-dev. Used in devnet/testnet.
static INSECURE_VERIFYING_KEY: Lazy<PreparedVerifyingKey<Bn254>> = Lazy::new(insecure_pvk);

/// test env salt service url
static TEST_SALT_URL: &str = "https://devsalt.openblock.vip/get_jwk";

/// prod env salt service url
static PROD_SALT_URL: &str = "https://ocean.zkpoint.org/get_jwk";

/// Load a fixed verifying key from zkLogin.vkey output. This is based on a local setup and should not use in production.
fn insecure_pvk() -> PreparedVerifyingKey<Bn254> {
    // Convert the Circom G1/G2/GT to arkworks G1/G2/GT
    let vk_alpha_1 = g1_affine_from_str_projective(&vec![
        Bn254FqElement::from_str(
            "10486870317575482004325641846182837176708253300684465201586876520614192607153",
        )
        .unwrap(),
        Bn254FqElement::from_str(
            "18289876836557182205892674936521124677204296577744626651090694285514486605677",
        )
        .unwrap(),
        Bn254FqElement::from_str("1").unwrap(),
    ])
    .unwrap();
    let vk_beta_2 = g2_affine_from_str_projective(&vec![
        vec![
            Bn254FqElement::from_str(
                "16423420719949315005607493052759952659822396864534263074696116094427677957135",
            )
            .unwrap(),
            Bn254FqElement::from_str(
                "10153784102660194152306160659369981418446853176359559679459141422566922426426",
            )
            .unwrap(),
        ],
        vec![
            Bn254FqElement::from_str(
                "682803926984143818491220402447680781735575385966789415023092266064541528013",
            )
            .unwrap(),
            Bn254FqElement::from_str(
                "14640144170568215402490069515698775130228899726999124519542844564350045122118",
            )
            .unwrap(),
        ],
        vec![
            Bn254FqElement::from_str("1").unwrap(),
            Bn254FqElement::from_str("0").unwrap(),
        ],
    ])
    .unwrap();
    let vk_gamma_2 = g2_affine_from_str_projective(&vec![
        vec![
            Bn254FqElement::from_str(
                "10857046999023057135944570762232829481370756359578518086990519993285655852781",
            )
            .unwrap(),
            Bn254FqElement::from_str(
                "11559732032986387107991004021392285783925812861821192530917403151452391805634",
            )
            .unwrap(),
        ],
        vec![
            Bn254FqElement::from_str(
                "8495653923123431417604973247489272438418190587263600148770280649306958101930",
            )
            .unwrap(),
            Bn254FqElement::from_str(
                "4082367875863433681332203403145435568316851327593401208105741076214120093531",
            )
            .unwrap(),
        ],
        vec![
            Bn254FqElement::from_str("1").unwrap(),
            Bn254FqElement::from_str("0").unwrap(),
        ],
    ])
    .unwrap();
    let vk_delta_2 = g2_affine_from_str_projective(&vec![
        vec![
            Bn254FqElement::from_str(
                "10940959420697183646670650299101185103421918085513623735611225602595925664657",
            )
            .unwrap(),
            Bn254FqElement::from_str(
                "4004281362142203418501307146379548927115410526248142450347678437522073743139",
            )
            .unwrap(),
        ],
        vec![
            Bn254FqElement::from_str(
                "4025895756808620791184697397120505973847755613006825609099299668764079031942",
            )
            .unwrap(),
            Bn254FqElement::from_str(
                "4165186226161261012936463791601345127047302001646843884844220197657942371020",
            )
            .unwrap(),
        ],
        vec![
            Bn254FqElement::from_str("1").unwrap(),
            Bn254FqElement::from_str("0").unwrap(),
        ],
    ])
    .unwrap();

    // Create a vector of G1Affine elements from the IC
    let mut vk_gamma_abc_g1 = Vec::new();
    for e in [
        vec![
            Bn254FqElement::from_str(
                "6150814249426173387512788987677074788517275529685834560250093039417966207906",
            )
            .unwrap(),
            Bn254FqElement::from_str(
                "21224878531699029571222356430699999942448701518163327382564022897740969848930",
            )
            .unwrap(),
            Bn254FqElement::from_str("1").unwrap(),
        ],
        vec![
            Bn254FqElement::from_str(
                "16767846576341167019758145053447377917719801326029759786311906458143260308555",
            )
            .unwrap(),
            Bn254FqElement::from_str(
                "14788489707772681310444456717806116626372883431266772205852779627926497267864",
            )
            .unwrap(),
            Bn254FqElement::from_str("1").unwrap(),
        ],
    ] {
        let g1 = g1_affine_from_str_projective(&e).unwrap();
        vk_gamma_abc_g1.push(g1);
    }

    let vk = VerifyingKey {
        alpha_g1: vk_alpha_1,
        beta_g2: vk_beta_2,
        gamma_g2: vk_gamma_2,
        delta_g2: vk_delta_2,
        gamma_abc_g1: vk_gamma_abc_g1,
    };

    // Convert the verifying key into the prepared form.
    PreparedVerifyingKey::from(vk)
}

/// Load a fixed verifying key from zkLogin.vkey output. This is based on a local setup and should not use in production.
fn global_pvk() -> PreparedVerifyingKey<Bn254> {
    // Convert the Circom G1/G2/GT to arkworks G1/G2/GT
    let vk_alpha_1 = g1_affine_from_str_projective(&vec![
        Bn254FqElement::from_str(
            "15997393655158587762706702897814105980647852716083912298619362291030838400332",
        )
        .unwrap(),
        Bn254FqElement::from_str(
            "249078137491133742188346429068949686302004544975955897672095915283146747520",
        )
        .unwrap(),
        Bn254FqElement::from_str("1").unwrap(),
    ])
    .unwrap();
    let vk_beta_2 = g2_affine_from_str_projective(&vec![
        vec![
            Bn254FqElement::from_str(
                "10878232154395585202296072008911709242930338413617289715079998155989018989065",
            )
            .unwrap(),
            Bn254FqElement::from_str(
                "9942894198646687164667763911504569320926965066383474395556026604547080535161",
            )
            .unwrap(),
        ],
        vec![
            Bn254FqElement::from_str(
                "7090533508802609231980133558445047657330012478887136952335891937362822315764",
            )
            .unwrap(),
            Bn254FqElement::from_str(
                "5282796614456722223203399940589276965991284443096860029827246452356105985218",
            )
            .unwrap(),
        ],
        vec![
            Bn254FqElement::from_str("1").unwrap(),
            Bn254FqElement::from_str("0").unwrap(),
        ],
    ])
    .unwrap();
    let vk_gamma_2 = g2_affine_from_str_projective(&vec![
        vec![
            Bn254FqElement::from_str(
                "10857046999023057135944570762232829481370756359578518086990519993285655852781",
            )
            .unwrap(),
            Bn254FqElement::from_str(
                "11559732032986387107991004021392285783925812861821192530917403151452391805634",
            )
            .unwrap(),
        ],
        vec![
            Bn254FqElement::from_str(
                "8495653923123431417604973247489272438418190587263600148770280649306958101930",
            )
            .unwrap(),
            Bn254FqElement::from_str(
                "4082367875863433681332203403145435568316851327593401208105741076214120093531",
            )
            .unwrap(),
        ],
        vec![
            Bn254FqElement::from_str("1").unwrap(),
            Bn254FqElement::from_str("0").unwrap(),
        ],
    ])
    .unwrap();
    let vk_delta_2 = g2_affine_from_str_projective(&vec![
        vec![
            Bn254FqElement::from_str(
                "20540701513399622432462655229369912959459433612115018233414095847885286227147",
            )
            .unwrap(),
            Bn254FqElement::from_str(
                "20400846012437396678160136877565180506579373005996170205179593299980188931948",
            )
            .unwrap(),
        ],
        vec![
            Bn254FqElement::from_str(
                "12846870561606676205725898362416576327729478251448592146319360169414464553137",
            )
            .unwrap(),
            Bn254FqElement::from_str(
                "766512298919331986486232284008562931079252544499502663019448488380879898855",
            )
            .unwrap(),
        ],
        vec![
            Bn254FqElement::from_str("1").unwrap(),
            Bn254FqElement::from_str("0").unwrap(),
        ],
    ])
    .unwrap();

    // Create a vector of G1Affine elements from the IC
    let mut vk_gamma_abc_g1 = Vec::new();
    for e in [
        vec![
            Bn254FqElement::from_str(
                "10817644616346835272624412620842439027939027888516174157613199674864823030158",
            )
            .unwrap(),
            Bn254FqElement::from_str(
                "16748378289388940842143793511377550706825115839326219569178428047626296570446",
            )
            .unwrap(),
            Bn254FqElement::from_str("1").unwrap(),
        ],
        vec![
            Bn254FqElement::from_str(
                "14342477796942791010365016630335003147779735368961387802143678121165827747232",
            )
            .unwrap(),
            Bn254FqElement::from_str(
                "15072171127465335322553884816330631969425119103378392239524187347351381522034",
            )
            .unwrap(),
            Bn254FqElement::from_str("1").unwrap(),
        ],
    ] {
        let g1 = g1_affine_from_str_projective(&e).unwrap();
        vk_gamma_abc_g1.push(g1);
    }

    let vk = VerifyingKey {
        alpha_g1: vk_alpha_1,
        beta_g2: vk_beta_2,
        gamma_g2: vk_gamma_2,
        delta_g2: vk_delta_2,
        gamma_abc_g1: vk_gamma_abc_g1,
    };

    // Convert the verifying key into the prepared form.
    PreparedVerifyingKey::from(vk)
}

/// Entry point for the ZkLogin API.
pub fn verify_zk_login(
    input: &ZkLoginInputs,
    max_epoch: u64,
    eph_pubkey_bytes: &[u8],
    all_jwk: &ImHashMap<JwkId, JWK>,
    env: &ZkLoginEnv,
) -> Result<(), FastCryptoError> {
    // Load the expected JWK based on (iss, kid).
    let (iss, kid) = (input.get_iss().to_string(), input.get_kid().to_string());
    let jwk = match all_jwk.get(&JwkId::new(iss.clone(), kid.clone())) {
        Some(jwk) => Ok(jwk.clone()),
        None => {
            let url = match env {
                ZkLoginEnv::Test => TEST_SALT_URL.to_string(),
                _ => PROD_SALT_URL.to_string(),
            };
            fetch_jwk_from_salt_service(url, &iss, &kid)
        }
    }?;

    // Decode modulus to bytes.
    let modulus = Base64UrlUnpadded::decode_vec(&jwk.n).map_err(|_| {
        FastCryptoError::GeneralError("Invalid Base64 encoded jwk modulus".to_string())
    })?;

    // Calculat all inputs hash and passed to the verification function.
    match verify_zk_login_proof_with_fixed_vk(
        env,
        &input.get_proof().as_arkworks()?,
        &[input.calculate_all_inputs_hash(eph_pubkey_bytes, &modulus, max_epoch)?],
    ) {
        Ok(true) => Ok(()),
        Ok(false) | Err(_) => Err(FastCryptoError::GeneralError(
            "Groth16 proof verify failed".to_string(),
        )),
    }
}

/// Verify a proof against its public inputs using the fixed verifying key.
pub fn verify_zk_login_proof_with_fixed_vk(
    usage: &ZkLoginEnv,
    proof: &Proof<Bn254>,
    public_inputs: &[Bn254Fr],
) -> Result<bool, FastCryptoError> {
    let vk = match usage {
        ZkLoginEnv::Prod => &GLOBAL_VERIFYING_KEY,
        ZkLoginEnv::Test => &INSECURE_VERIFYING_KEY,
    };
    Groth16::<Bn254>::verify_with_processed_vk(vk, public_inputs, proof)
        .map_err(|e| FastCryptoError::GeneralError(e.to_string()))
}

/// Verify that the given parameters (name, value, aud, iss and salt_hash) were used to generate the
/// given address.
pub fn verify_zk_login_id(
    address: &[u8],
    name: &str,
    value: &str,
    aud: &str,
    iss: &str,
    salt_hash: &str,
) -> FastCryptoResult<()> {
    let address_seed = gen_address_seed_with_salt_hash(salt_hash, name, value, aud)?;
    verify_zk_login_iss(address, &address_seed, iss)
}

/// Verify that the given parameters (address_seed and iss) were used to generate the given address.
pub fn verify_zk_login_iss(address: &[u8], address_seed: &str, iss: &str) -> FastCryptoResult<()> {
    let reconstructed_address =
        get_zk_login_address(&Bn254FrElement::from_str(address_seed)?, iss)?;
    match reconstructed_address == address {
        true => Ok(()),
        false => Err(FastCryptoError::InvalidProof),
    }
}
