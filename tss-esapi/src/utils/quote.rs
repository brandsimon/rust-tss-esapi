// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::error::Error;
use crate::error::Result;
use crate::WrapperErrorKind;
use crate::{
    abstraction::public::AssociatedTpmCurve,
    interface_types::algorithm::HashingAlgorithm,
    structures::{
        Attest, AttestInfo, DigestList, EccSignature, PcrSelectionList, Public, QuoteInfo,
        Signature,
    },
    traits::Marshall,
};
use digest::{Digest, DynDigest};

use ecdsa::{
    hazmat::{DigestPrimitive, VerifyPrimitive},
    PrimeCurve, SignatureSize, VerifyingKey,
};
use elliptic_curve::{
    generic_array::ArrayLength,
    point::AffinePoint,
    sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint},
    CurveArithmetic, FieldBytesSize,
};
use signature::{hazmat::PrehashVerifier, Verifier};

#[cfg(feature = "rsa")]
use rsa::{pkcs1v15, pss, RsaPublicKey};

fn verify_ecdsa<C>(
    public: &Public,
    message: &[u8],
    signature: &EccSignature,
    hashing_algorithm: HashingAlgorithm,
) -> Result<bool>
where
    C: PrimeCurve + CurveArithmetic + DigestPrimitive + AssociatedTpmCurve,
    AffinePoint<C>: VerifyPrimitive<C> + FromEncodedPoint<C> + ToEncodedPoint<C>,
    SignatureSize<C>: ArrayLength<u8>,
    FieldBytesSize<C>: ModulusSize,
{
    let Ok(signature) = ecdsa::Signature::<C>::try_from(signature.clone()) else {
        return Ok(false);
    };
    let Ok(public) = elliptic_curve::PublicKey::<C>::try_from(public) else {
        println!("public convert failed");
        return Ok(false);
    };

    let verifying_key = VerifyingKey::from(public);

    match hashing_algorithm {
        #[cfg(feature = "sha1")]
        HashingAlgorithm::Sha1 => {
            let hash = sha1::Sha1::digest(&message);
            Ok(verifying_key.verify_prehash(&hash, &signature).is_ok())
        }
        #[cfg(feature = "sha2")]
        HashingAlgorithm::Sha256 => {
            let hash = sha2::Sha256::digest(&message);
            Ok(verifying_key.verify_prehash(&hash, &signature).is_ok())
        }
        #[cfg(feature = "sha2")]
        HashingAlgorithm::Sha384 => {
            let hash = sha2::Sha384::digest(&message);
            Ok(verifying_key.verify_prehash(&hash, &signature).is_ok())
        }
        #[cfg(feature = "sha2")]
        HashingAlgorithm::Sha512 => {
            let hash = sha2::Sha512::digest(&message);
            Ok(verifying_key.verify_prehash(&hash, &signature).is_ok())
        }
        _ => {
            return Err(Error::WrapperError(WrapperErrorKind::UnsupportedParam));
        }
    }
}

#[cfg(feature = "rsa")]
fn verify_rsa_pss(
    public: &Public,
    message: &[u8],
    signature: &pss::Signature,
    hashing_algorithm: HashingAlgorithm,
) -> Result<bool> {
    let rsa_key = RsaPublicKey::try_from(public)?;

    match hashing_algorithm {
        #[cfg(feature = "sha1")]
        HashingAlgorithm::Sha1 => {
            let verifying_key = pss::VerifyingKey::<sha1::Sha1>::from(rsa_key);
            Ok(verifying_key.verify(message, signature).is_ok())
        }
        #[cfg(feature = "sha2")]
        HashingAlgorithm::Sha256 => {
            let verifying_key = pss::VerifyingKey::<sha2::Sha256>::from(rsa_key);
            Ok(verifying_key.verify(message, signature).is_ok())
        }
        #[cfg(feature = "sha2")]
        HashingAlgorithm::Sha384 => {
            let verifying_key = pss::VerifyingKey::<sha2::Sha384>::from(rsa_key);
            Ok(verifying_key.verify(message, signature).is_ok())
        }
        #[cfg(feature = "sha2")]
        HashingAlgorithm::Sha512 => {
            let verifying_key = pss::VerifyingKey::<sha2::Sha512>::from(rsa_key);
            Ok(verifying_key.verify(message, signature).is_ok())
        }
        _ => {
            return Err(Error::WrapperError(WrapperErrorKind::UnsupportedParam));
        }
    }
}

#[cfg(feature = "rsa")]
fn verify_rsa_pkcs1v15(
    public: &Public,
    message: &[u8],
    signature: &pkcs1v15::Signature,
    hashing_algorithm: HashingAlgorithm,
) -> Result<bool> {
    let rsa_key = RsaPublicKey::try_from(public)?;

    match hashing_algorithm {
        #[cfg(feature = "sha1")]
        HashingAlgorithm::Sha1 => {
            let verifying_key = pkcs1v15::VerifyingKey::<sha1::Sha1>::from(rsa_key);
            Ok(verifying_key.verify(message, signature).is_ok())
        }
        #[cfg(feature = "sha2")]
        HashingAlgorithm::Sha256 => {
            let verifying_key = pkcs1v15::VerifyingKey::<sha2::Sha256>::from(rsa_key);
            Ok(verifying_key.verify(message, signature).is_ok())
        }
        #[cfg(feature = "sha2")]
        HashingAlgorithm::Sha384 => {
            let verifying_key = pkcs1v15::VerifyingKey::<sha2::Sha384>::from(rsa_key);
            Ok(verifying_key.verify(message, signature).is_ok())
        }
        #[cfg(feature = "sha2")]
        HashingAlgorithm::Sha512 => {
            let verifying_key = pkcs1v15::VerifyingKey::<sha2::Sha512>::from(rsa_key);
            Ok(verifying_key.verify(message, signature).is_ok())
        }
        _ => {
            return Err(Error::WrapperError(WrapperErrorKind::UnsupportedParam));
        }
    }
}

fn checkquote_pcr_digests(
    quote: &QuoteInfo,
    selections: &PcrSelectionList,
    digests: &DigestList,
    hash_alg: HashingAlgorithm,
) -> Result<bool> {
    if selections != quote.pcr_selection() {
        return Ok(false);
    }
    let digests_val = digests.value();
    let mut digest_pos = 0;
    let mut hasher: Box<dyn DynDigest> = match hash_alg {
        #[cfg(feature = "sha1")]
        HashingAlgorithm::Sha1 => Box::new(sha1::Sha1::new()),
        #[cfg(feature = "sha2")]
        HashingAlgorithm::Sha256 => Box::new(sha2::Sha256::new()),
        #[cfg(feature = "sha2")]
        HashingAlgorithm::Sha384 => Box::new(sha2::Sha384::new()),
        #[cfg(feature = "sha2")]
        HashingAlgorithm::Sha512 => Box::new(sha2::Sha512::new()),
        _ => {
            return Err(Error::WrapperError(WrapperErrorKind::UnsupportedParam));
        }
    };

    for selection in selections.get_selections() {
        let sel_count = selection.selected().len();
        if digest_pos + sel_count > digests.len() {
            return Err(Error::WrapperError(WrapperErrorKind::WrongParamSize));
        }
        for _ in 0..sel_count {
            hasher.update(&digests_val[digest_pos]);
            digest_pos += 1;
        }
    }
    if digest_pos != digests.len() {
        return Err(Error::WrapperError(WrapperErrorKind::WrongParamSize));
    }
    let digest = hasher.finalize().to_vec();
    if digest != quote.pcr_digest().as_bytes() {
        return Ok(false);
    }
    return Ok(true);
}

/// Verify a quote
///
/// # Arguments
/// * `attest` - Attestation data containing a quote
/// * `signature` - Signature for the attestation data
/// * `public` - TPM2 public struct which contains the public key for verification
/// * `pcr_data` - Optional pcr values to verify
/// * `qualifying_data` - qualifying_data to verify
///
/// # Returns
/// The command returns a boolean
///
/// # Errors
/// * if the qualifying data provided is too long, a `WrongParamSize` wrapper error will be returned
///
/// # Examples
///
/// ```rust
/// # use std::convert::TryFrom;
/// # use tss_esapi::{
/// #     attributes::SessionAttributes,
/// #     abstraction::{ak, ek, AsymmetricAlgorithmSelection},
/// #     constants::SessionType, Context,
/// #     interface_types::{
/// #         algorithm::{HashingAlgorithm, SignatureSchemeAlgorithm},
/// #         ecc::EccCurve,
/// #     },
/// #     structures::{
/// #         Data, PcrSelectionListBuilder, PcrSlot,
/// #         SignatureScheme, SymmetricDefinition,
/// #     },
/// #     TctiNameConf,
/// #     utils,
/// # };
/// # let mut context =
/// #     Context::new(
/// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
/// #     ).expect("Failed to create Context");
/// # let session = context
/// #     .start_auth_session(
/// #         None,
/// #         None,
/// #         None,
/// #         SessionType::Hmac,
/// #         SymmetricDefinition::AES_256_CFB,
/// #         tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256,
/// #     )
/// #     .expect("Failed to create session")
/// #     .expect("Received invalid handle");
/// # let (session_attributes, session_attributes_mask) = SessionAttributes::builder()
/// #     .with_decrypt(true)
/// #     .with_encrypt(true)
/// #     .build();
/// # context.tr_sess_set_attributes(session, session_attributes, session_attributes_mask)
/// #     .expect("Failed to set attributes on session");
/// # context.set_sessions((Some(session), None, None));
/// # let qualifying_data = vec![0xff; 16];
/// # let ek_ecc = ek::create_ek_object(
/// #     &mut context,
/// #     AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP256),
/// #     None,
/// # )
/// # .unwrap();
/// # let ak_res = ak::create_ak(
/// #     &mut context,
/// #     ek_ecc,
/// #     HashingAlgorithm::Sha256,
/// #     AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP256),
/// #     SignatureSchemeAlgorithm::EcDsa,
/// #     None,
/// #     None,
/// # )
/// # .unwrap();
/// # let ak_ecc = ak::load_ak(
/// #     &mut context,
/// #     ek_ecc,
/// #     None,
/// #     ak_res.out_private,
/// #     ak_res.out_public.clone(),
/// # )
/// # .unwrap();
/// # let pcr_selection_list = PcrSelectionListBuilder::new()
/// #     .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot2])
/// #     .build()
/// #     .expect("Failed to create PcrSelectionList");
/// let (attest, signature) = context
///     .quote(
///         ak_ecc,
///         Data::try_from(qualifying_data.clone()).unwrap(),
///         SignatureScheme::Null,
///         pcr_selection_list.clone(),
///     )
///     .expect("Failed to get a quote");
/// let (_update_counter, pcr_sel, pcr_data) = context
///     .execute_without_session(|ctx| ctx.pcr_read(pcr_selection_list))
///     .unwrap();
/// let public = ak_res.out_public;
/// utils::checkquote(
///     &attest,
///     &signature,
///     &public,
///     &Some((pcr_sel.clone(), pcr_data.clone())),
///     &qualifying_data
/// )
/// .unwrap();
/// ```
pub fn checkquote(
    attest: &Attest,
    signature: &Signature,
    public: &Public,
    pcr_data: &Option<(PcrSelectionList, DigestList)>,
    qualifying_data: &Vec<u8>,
) -> Result<bool> {
    let quote = match attest.attested() {
        AttestInfo::Quote { info } => info,
        _ => {
            return Err(Error::WrapperError(WrapperErrorKind::InvalidParam));
        }
    };

    let bytes = attest.marshall()?;

    let mut hash_alg = None;
    match (public, signature) {
        (Public::Ecc { parameters, .. }, _) => {
            macro_rules! impl_check_ecdsa {
                ($curve: ty) => {
                    if parameters.ecc_curve() == <$curve>::TPM_CURVE {
                        let Signature::EcDsa(sig) = signature else {
                            return Ok(false);
                        };
                        println!("hash_alg: {:?}", sig.hashing_algorithm());

                        if !verify_ecdsa::<$curve>(&public, &bytes, &sig, sig.hashing_algorithm())?
                        {
                            println!("verification failed");
                            return Ok(false);
                        }

                        hash_alg = Some(sig.hashing_algorithm());
                        println!("hash_alg: {hash_alg:?}");
                    }
                };
            }

            //#[cfg(feature = "p192")]
            //impl_check_ecdsa!(p192::NistP192);
            #[cfg(feature = "p224")]
            impl_check_ecdsa!(p224::NistP224);
            #[cfg(feature = "p256")]
            impl_check_ecdsa!(p256::NistP256);
            #[cfg(feature = "p384")]
            impl_check_ecdsa!(p384::NistP384);
            //#[cfg(feature = "p521")]
            //impl_check_ecdsa!(p521::NistP521);
            //#[cfg(feature = "sm2")]
            //impl_check_ecdsa!(sm2::Sm2);
        }
        #[cfg(feature = "rsa")]
        (Public::Rsa { .. }, sig @ Signature::RsaSsa(pkcs_sig)) => {
            let Ok(sig) = pkcs1v15::Signature::try_from(sig.clone()) else {
                return Ok(false);
            };

            if !verify_rsa_pkcs1v15(public, &bytes, &sig, pkcs_sig.hashing_algorithm())? {
                return Ok(false);
            }
            hash_alg = Some(pkcs_sig.hashing_algorithm());
        }
        #[cfg(feature = "rsa")]
        (Public::Rsa { .. }, sig @ Signature::RsaPss(pkcs_sig)) => {
            let Ok(sig) = pss::Signature::try_from(sig.clone()) else {
                return Ok(false);
            };

            if !verify_rsa_pss(public, &bytes, &sig, pkcs_sig.hashing_algorithm())? {
                return Ok(false);
            }
            hash_alg = Some(pkcs_sig.hashing_algorithm());
        }
        _ => {
            return Ok(false);
        }
    };

    let Some(hash_alg) = hash_alg else {
        return Ok(false);
    };
    if qualifying_data != attest.extra_data().as_bytes() {
        return Ok(false);
    }
    match pcr_data {
        Some((selections, digests)) => {
            if !checkquote_pcr_digests(&quote, &selections, &digests, hash_alg)? {
                return Ok(false);
            }
        }
        None => {}
    }
    return Ok(true);
}
