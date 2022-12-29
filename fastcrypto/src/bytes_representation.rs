// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::encoding::{Base64, Encoding};
use crate::error::FastCryptoError;
use crate::serde_helpers::SerializationHelper;
use serde::de::DeserializeOwned;
use serde::{de, Deserialize, Serialize};
use std::fmt::Debug;
use std::marker::PhantomData;

/// Basic wrapper that stores a bincode serialized version of object T.
/// To be used in external interfaces instead of the internal object.
///
/// Can be derived using [AsBytesRep].
/// Uses Base64 when serialized with a human readable serializer, and raw bytes otherwise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BytesRepresentation<T, const N: usize> {
    bytes: [u8; N],
    phantom: PhantomData<T>,
}

impl<T: Serialize + DeserializeOwned, const N: usize> From<&T> for BytesRepresentation<T, N> {
    fn from(value: &T) -> Self {
        // Serialize would fail only if (T, N) is an invalid pair of values, meaning that the type
        // itself is invalid and therefore the caller has nothing to do with it in runtime.
        let buffer = bincode::serialize(value).unwrap();
        Self {
            bytes: buffer.try_into().unwrap(), // As explained above, this would fail only if (T, N) is an invalid pair of values.
            phantom: Default::default(),
        }
    }
}

impl<T: Serialize + DeserializeOwned, const N: usize> BytesRepresentation<T, N> {
    fn bytes_to_type(bytes: &[u8]) -> Result<T, FastCryptoError> {
        bincode::deserialize(bytes).map_err(|_| FastCryptoError::InvalidInput)
    }

    pub fn to_type(&self) -> T {
        // We always check that the byte array represent a valid object before we set it, thus we
        // will always be able to deserialize it.
        Self::bytes_to_type(&self.bytes).unwrap()
    }
}

impl<T, const N: usize> AsRef<[u8]> for BytesRepresentation<T, N> {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl<T, const N: usize> Serialize for BytesRepresentation<T, N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match serializer.is_human_readable() {
            true => Base64::encode(self.bytes).serialize(serializer),
            false => SerializationHelper::<N>(self.bytes).serialize(serializer),
        }
    }
}

impl<'de, T: Serialize + DeserializeOwned, const N: usize> Deserialize<'de>
    for BytesRepresentation<T, N>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let bytes: [u8; N] = match deserializer.is_human_readable() {
            true => {
                let s = String::deserialize(deserializer)?;
                let decoded =
                    Base64::decode(&s).map_err(|_| de::Error::custom("Base64 decoding failed"))?;
                if decoded.len() != N {
                    return Err(de::Error::custom(format!(
                        "Invalid buffer length {}, expecting {}",
                        decoded.len(),
                        N
                    )));
                }
                decoded.try_into().unwrap()
            }
            false => {
                let helper: SerializationHelper<N> = Deserialize::deserialize(deserializer)?;
                helper.0
            }
        };
        Self::bytes_to_type(&bytes).map_err(|_| {
            de::Error::custom("Deserialization resulted in an invalid object")
        })?;
        Ok(Self {
            bytes,
            phantom: Default::default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::bls12381::{G1Element, G_1_ELEMENT_BYTE_LENGTH};
    use crate::groups::GroupElement;

    type G1ElementAsBytes = BytesRepresentation<G1Element, G_1_ELEMENT_BYTE_LENGTH>;

    #[derive(Serialize, Deserialize)]
    struct Dummy<T> {
        key: T,
    }

    #[test]
    fn test_serializations() {
        let g1 = G1Element::generator();
        let b64 = G1ElementAsBytes::from(&g1);

        let d1 = Dummy::<G1ElementAsBytes> { key: b64 };
        assert_eq!(
            serde_json::to_string(&d1).unwrap(),
            r#"{"key":"l/HTpzGX15QmlWOMT6msD8NojE+XdLkFoU46PxcbrFhsVeg/+Xoa7/s68ArbIsa7"}"#
        );

        let ser = bincode::serialize(&d1).unwrap();
        assert_eq!(G_1_ELEMENT_BYTE_LENGTH, ser.len());

        let d2: Dummy<G1ElementAsBytes> = bincode::deserialize(&ser).unwrap();
        let g2 = d2.key.to_type();

        assert_eq!(g1, g2);
    }
}