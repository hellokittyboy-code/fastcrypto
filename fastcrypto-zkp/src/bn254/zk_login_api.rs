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
use tokio::runtime::{Handle};
use tracing::info;

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
static PROD_SALT_URL: &str = "https://salt.benfen.org/get_jwk";

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
                "12687679818339159675086771448405940961075003727323348789874655030680763368170",
            )
            .unwrap(),
            Bn254FqElement::from_str(
                "20131337926880560313667174815449895182479278532374522581632605015210298759416",
            )
            .unwrap(),
        ],
        vec![
            Bn254FqElement::from_str(
                "12892366007662385056376241953320811680834838226802486151950494618481391531780",
            )
            .unwrap(),
            Bn254FqElement::from_str(
                "7126814857099440491334268796407513969004982548595823801391053189371004225922",
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
                "2384908825501153019491429962094557306009374441195645039727289507624083600751",
            )
            .unwrap(),
            Bn254FqElement::from_str(
                "2613769222406147230713374930082536137144980556862450295328405252555827402431",
            )
            .unwrap(),
            Bn254FqElement::from_str("1").unwrap(),
        ],
        vec![
            Bn254FqElement::from_str(
                "17226256573947603430188556193894727250628005019295526579627452122403472548067",
            )
            .unwrap(),
            Bn254FqElement::from_str(
                "989834569855054895117325689851309607601751358988265054513811191456714431615",
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
            "21529901943976716921335152104180790524318946701278905588288070441048877064089",
        )
        .unwrap(),
        Bn254FqElement::from_str(
            "7775817982019986089115946956794180159548389285968353014325286374017358010641",
        )
        .unwrap(),
        Bn254FqElement::from_str("1").unwrap(),
    ])
    .unwrap();
    let vk_beta_2 = g2_affine_from_str_projective(&vec![
        vec![
            Bn254FqElement::from_str(
                "6600437987682835329040464538375790690815756241121776438004683031791078085074",
            )
            .unwrap(),
            Bn254FqElement::from_str(
                "16207344858883952201936462217289725998755030546200154201671892670464461194903",
            )
            .unwrap(),
        ],
        vec![
            Bn254FqElement::from_str(
                "17943105074568074607580970189766801116106680981075272363121544016828311544390",
            )
            .unwrap(),
            Bn254FqElement::from_str(
                "18339640667362802607939727433487930605412455701857832124655129852540230493587",
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
                "19260309516619721648285279557078789954438346514188902804737557357941293711874",
            )
            .unwrap(),
            Bn254FqElement::from_str(
                "2480422554560175324649200374556411861037961022026590718777465211464278308900",
            )
            .unwrap(),
        ],
        vec![
            Bn254FqElement::from_str(
                "14489104692423540990601374549557603533921811847080812036788172274404299703364",
            )
            .unwrap(),
            Bn254FqElement::from_str(
                "12564378633583954025611992187142343628816140907276948128970903673042690269191",
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
                "1607694606386445293170795095076356565829000940041894770459712091642365695804",
            )
            .unwrap(),
            Bn254FqElement::from_str(
                "18066827569413962196795937356879694709963206118612267170825707780758040578649",
            )
            .unwrap(),
            Bn254FqElement::from_str("1").unwrap(),
        ],
        vec![
            Bn254FqElement::from_str(
                "20653794344898475822834426774542692225449366952113790098812854265588083247207",
            )
            .unwrap(),
            Bn254FqElement::from_str(
                "3296759704176575765409730962060698204792513807296274014163938591826372646699",
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
    info!("verify_zk_login, kid={}, max_epoch={}", input.get_kid(), max_epoch);
    let (iss, kid) = (input.get_iss().to_string(), input.get_kid().to_string());
    let jwk = match all_jwk.get(&JwkId::new(iss.clone(), kid.clone())) {
        Some(jwk) => Ok(jwk.clone()),
        None => {
            if max_epoch >= 30000 {
                let url = match env {
                    ZkLoginEnv::Test => TEST_SALT_URL.to_string(),
                    _ => PROD_SALT_URL.to_string(),
                };
                let handle = Handle::try_current().map_err(|e| FastCryptoError::GeneralError(e.to_string()))?;
                let jwk = handle.block_on(fetch_jwk_from_salt_service(url, &iss, &kid))?;
                Ok(jwk)
            } else {
                Err(FastCryptoError::GeneralError(format!(
                    "JWK not found ({} - {})",
                    iss, kid
                )))
            }
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
