//! Implementation of the Olaf protocol (<https://eprint.iacr.org/2023/899>), which is composed of the Distributed
//! Key Generation (DKG) protocol SimplPedPoP and the Threshold Signing protocol FROST.

/// Implementation of the FROST protocol.
pub mod frost;
/// Implementation of the SimplPedPoP protocol.
pub mod simplpedpop;

use crate::{SignatureError, SigningKey, VerifyingKey, KEYPAIR_LENGTH, SECRET_KEY_LENGTH};
use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, EdwardsPoint, Scalar};
use merlin::Transcript;

pub(super) const MINIMUM_THRESHOLD: u16 = 2;
pub(super) const GENERATOR: EdwardsPoint = ED25519_BASEPOINT_POINT;
pub(crate) const SCALAR_LENGTH: usize = 32;
pub(super) const COMPRESSED_EDWARDS_LENGTH: usize = 32;

/// The threshold public key generated in the SimplPedPoP protocol, used to validate the threshold signatures of the FROST protocol.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ThresholdPublicKey(pub(crate) VerifyingKey);

/// The verifying share of a participant generated in the SimplPedPoP protocol, used to verify its signatures shares in the FROST protocol.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VerifyingShare(pub(crate) VerifyingKey);

/// The signing keypair of a participant generated in the SimplPedPoP protocol, used to produce its signatures shares in the FROST protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningKeypair(pub(crate) SigningKey);

impl SigningKeypair {
    /// Serializes `SigningKeypair` to bytes.
    pub fn to_bytes(&self) -> [u8; KEYPAIR_LENGTH] {
        self.0.to_keypair_bytes()
    }

    /// Deserializes a `SigningKeypair` from bytes.
    pub fn from_bytes(bytes: &[u8; KEYPAIR_LENGTH]) -> Result<SigningKeypair, SignatureError> {
        let mut secret_key = [0; SECRET_KEY_LENGTH];
        secret_key.copy_from_slice(&bytes[..SECRET_KEY_LENGTH]);

        let mut verifying_key_bytes = [0; SECRET_KEY_LENGTH];
        verifying_key_bytes.copy_from_slice(&bytes[SECRET_KEY_LENGTH..]);

        let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes)?;

        let signing_key = SigningKey {
            secret_key,
            verifying_key,
        };

        Ok(SigningKeypair(signing_key))
    }
}

/// The identifier of a participant, which is the same in the SimplPedPoP protocol and in the FROST protocol.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Identifier(pub(crate) Scalar);

impl Identifier {
    pub(super) fn generate(recipients_hash: &[u8; 16], index: u16) -> Identifier {
        let mut pos = Transcript::new(b"Identifier");
        pos.append_message(b"RecipientsHash", recipients_hash);
        pos.append_message(b"i", &index.to_le_bytes()[..]);

        let mut buf = [0; 64];
        pos.challenge_bytes(b"identifier", &mut buf);

        Identifier(Scalar::from_bytes_mod_order_wide(&buf))
    }
}

pub(crate) fn scalar_from_canonical_bytes(bytes: [u8; 32]) -> Option<Scalar> {
    let key = Scalar::from_canonical_bytes(bytes);

    // Note: this is a `CtOption` so we have to do this to extract the value.
    if bool::from(key.is_none()) {
        return None;
    }

    Some(key.unwrap())
}

#[cfg(test)]
pub(crate) mod test_utils {
    use super::MINIMUM_THRESHOLD;
    use crate::{
        olaf::{simplpedpop::Parameters, SigningKeypair},
        SigningKey,
    };
    use ed25519::signature::Keypair;
    use rand::{thread_rng, Rng};

    const MAXIMUM_PARTICIPANTS: u16 = 2;
    const MINIMUM_PARTICIPANTS: u16 = 2;

    pub(crate) fn generate_parameters() -> Parameters {
        let mut rng = thread_rng();
        let participants = rng.gen_range(MINIMUM_PARTICIPANTS..=MAXIMUM_PARTICIPANTS);
        let threshold = rng.gen_range(MINIMUM_THRESHOLD..=participants);

        Parameters {
            participants,
            threshold,
        }
    }

    #[test]
    fn test_signing_keypair_serialization() {
        let mut rng = thread_rng();
        let keypair = SigningKeypair(SigningKey::generate(&mut rng));

        let bytes = keypair.to_bytes();
        let deserialized_keypair = SigningKeypair::from_bytes(&bytes).unwrap();

        assert_eq!(keypair, deserialized_keypair);
    }
}
