/*
 * Copyright (c) 2009 IETF Trust and the persons identified as the
 * document authors. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright notice, this list of conditions and the following
 *   disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
 *   following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 * - Neither the name of Internet Society, IETF or IETF Trust, nor the names of specific contributors, may be used to
 *   endorse or promote products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 * Wire definitions below are derived from RFC 2203 and RFC 5403.
 */

use crate::rpc::codec::{DecodeError, Decoder, EncodeError, Encoder};

pub const RPCSEC_GSS: u32 = 6;
pub const MAX_SEQUENCE_NUMBER: u32 = 0x8000_0000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Version {
    V1 = 1,
    V2 = 2,
}

impl Version {
    fn from_code(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::V1),
            2 => Some(Self::V2),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Procedure {
    Data = 0,
    Init = 1,
    ContinueInit = 2,
    Destroy = 3,
    BindChannel = 4,
}

impl Procedure {
    fn from_code(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Data),
            1 => Some(Self::Init),
            2 => Some(Self::ContinueInit),
            3 => Some(Self::Destroy),
            4 => Some(Self::BindChannel),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Service {
    None = 1,
    Integrity = 2,
    Privacy = 3,
    ChannelProtection = 4,
}

impl Service {
    fn from_code(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::None),
            2 => Some(Self::Integrity),
            3 => Some(Self::Privacy),
            4 => Some(Self::ChannelProtection),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Credential {
    pub version: Version,
    pub procedure: Procedure,
    pub sequence: u32,
    pub service: Service,
    pub handle: Vec<u8>,
}

impl Credential {
    pub fn decode(input: &[u8], limits: GssLimits) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(input);
        let value = Self {
            version: decoder.read_enum("RPCSEC_GSS version", Version::from_code)?,
            procedure: decoder.read_enum("RPCSEC_GSS procedure", Procedure::from_code)?,
            sequence: decoder.read_u32()?,
            service: decoder.read_enum("RPCSEC_GSS service", Service::from_code)?,
            handle: decoder.read_opaque("RPCSEC_GSS context handle", limits.max_handle_bytes)?,
        };
        decoder.finish()?;
        value
            .validate()
            .map_err(|field| DecodeError::InvalidDiscriminant { kind: field, value: 0 })?;
        Ok(value)
    }

    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut encoder = Encoder::new();
        encoder.write_u32(self.version as u32);
        encoder.write_u32(self.procedure as u32);
        encoder.write_u32(self.sequence);
        encoder.write_u32(self.service as u32);
        encoder.write_opaque(&self.handle)?;
        Ok(encoder.into_bytes())
    }

    fn validate(&self) -> Result<(), &'static str> {
        if self.version == Version::V1
            && (self.procedure == Procedure::BindChannel || self.service == Service::ChannelProtection)
        {
            return Err("RPCSEC_GSSv1 extension");
        }
        if matches!(self.procedure, Procedure::Data | Procedure::Destroy | Procedure::BindChannel)
            && self.sequence >= MAX_SEQUENCE_NUMBER
        {
            return Err("RPCSEC_GSS sequence");
        }
        if self.procedure == Procedure::BindChannel && self.service != Service::None {
            return Err("RPCSEC_GSS channel binding service");
        }
        if self.procedure == Procedure::Init && !self.handle.is_empty() {
            return Err("RPCSEC_GSS INIT handle");
        }
        if matches!(
            self.procedure,
            Procedure::ContinueInit | Procedure::Data | Procedure::Destroy | Procedure::BindChannel
        ) && self.handle.is_empty()
        {
            return Err("RPCSEC_GSS context handle");
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GssLimits {
    pub max_handle_bytes: usize,
    pub max_token_bytes: usize,
    pub max_mic_bytes: usize,
    pub max_protected_body_bytes: usize,
    pub max_channel_binding_bytes: usize,
    pub max_channel_prefix_bytes: usize,
    pub max_oid_bytes: usize,
    pub max_preference_count: usize,
}

impl Default for GssLimits {
    fn default() -> Self {
        Self {
            max_handle_bytes: 1024,
            max_token_bytes: 1024 * 1024,
            max_mic_bytes: 64 * 1024,
            max_protected_body_bytes: 16 * 1024 * 1024,
            max_channel_binding_bytes: 64 * 1024,
            max_channel_prefix_bytes: 256,
            max_oid_bytes: 256,
            max_preference_count: 32,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitArgs {
    pub token: Vec<u8>,
}

impl InitArgs {
    pub fn decode(input: &[u8], limits: GssLimits) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(input);
        let value = Self {
            token: decoder.read_opaque("RPCSEC_GSS init token", limits.max_token_bytes)?,
        };
        decoder.finish()?;
        Ok(value)
    }

    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut encoder = Encoder::new();
        encoder.write_opaque(&self.token)?;
        Ok(encoder.into_bytes())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitResult {
    pub handle: Vec<u8>,
    pub major_status: u32,
    pub minor_status: u32,
    pub sequence_window: u32,
    pub token: Vec<u8>,
}

impl InitResult {
    pub fn decode(input: &[u8], limits: GssLimits) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(input);
        let value = Self {
            handle: decoder.read_opaque("RPCSEC_GSS result handle", limits.max_handle_bytes)?,
            major_status: decoder.read_u32()?,
            minor_status: decoder.read_u32()?,
            sequence_window: decoder.read_u32()?,
            token: decoder.read_opaque("RPCSEC_GSS result token", limits.max_token_bytes)?,
        };
        decoder.finish()?;
        Ok(value)
    }

    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut encoder = Encoder::new();
        encoder.write_opaque(&self.handle)?;
        encoder.write_u32(self.major_status);
        encoder.write_u32(self.minor_status);
        encoder.write_u32(self.sequence_window);
        encoder.write_opaque(&self.token)?;
        Ok(encoder.into_bytes())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntegrityBody {
    /// XDR of `sequence number + procedure arguments/results`.
    pub protected: Vec<u8>,
    pub checksum: Vec<u8>,
}

impl IntegrityBody {
    pub fn decode(input: &[u8], limits: GssLimits) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(input);
        let value = Self {
            protected: decoder.read_opaque("RPCSEC_GSS integrity body", limits.max_protected_body_bytes)?,
            checksum: decoder.read_opaque("RPCSEC_GSS integrity MIC", limits.max_mic_bytes)?,
        };
        decoder.finish()?;
        Ok(value)
    }

    pub fn embedded_sequence(&self) -> Result<u32, DecodeError> {
        let mut decoder = Decoder::new(&self.protected);
        decoder.read_u32()
    }

    pub fn procedure_body(&self) -> Result<&[u8], DecodeError> {
        let mut decoder = Decoder::new(&self.protected);
        decoder.read_u32()?;
        Ok(&self.protected[decoder.position()..])
    }

    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut encoder = Encoder::new();
        encoder.write_opaque(&self.protected)?;
        encoder.write_opaque(&self.checksum)?;
        Ok(encoder.into_bytes())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyBody {
    pub wrapped: Vec<u8>,
}

impl PrivacyBody {
    pub fn decode(input: &[u8], limits: GssLimits) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(input);
        let value = Self {
            wrapped: decoder.read_opaque("RPCSEC_GSS privacy body", limits.max_protected_body_bytes)?,
        };
        decoder.finish()?;
        Ok(value)
    }

    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut encoder = Encoder::new();
        encoder.write_opaque(&self.wrapped)?;
        Ok(encoder.into_bytes())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelBindingVerifierArgs {
    pub prefix: Vec<u8>,
    pub hash_oid: Vec<u8>,
    pub mic: Vec<u8>,
}

impl ChannelBindingVerifierArgs {
    pub fn decode(input: &[u8], limits: GssLimits) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(input);
        let value = Self {
            prefix: decoder.read_opaque("RPCSEC_GSS channel prefix", limits.max_channel_prefix_bytes)?,
            hash_oid: decoder.read_opaque("RPCSEC_GSS channel hash OID", limits.max_oid_bytes)?,
            mic: decoder.read_opaque("RPCSEC_GSS channel MIC", limits.max_mic_bytes)?,
        };
        decoder.finish()?;
        Ok(value)
    }

    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut encoder = Encoder::new();
        encoder.write_opaque(&self.prefix)?;
        encoder.write_opaque(&self.hash_oid)?;
        encoder.write_opaque(&self.mic)?;
        Ok(encoder.into_bytes())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChannelBindingStatus {
    Ok,
    PrefixNotSupported(Vec<Vec<u8>>),
    HashNotSupported(Vec<Vec<u8>>),
}

impl ChannelBindingStatus {
    fn encode_into(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Ok => encoder.write_u32(0),
            Self::PrefixNotSupported(prefixes) => {
                encoder.write_u32(1);
                encoder.write_u32(u32::try_from(prefixes.len()).map_err(|_| EncodeError::TooLarge(prefixes.len()))?);
                for prefix in prefixes {
                    encoder.write_opaque(prefix)?;
                }
            },
            Self::HashNotSupported(oids) => {
                encoder.write_u32(2);
                encoder.write_u32(u32::try_from(oids.len()).map_err(|_| EncodeError::TooLarge(oids.len()))?);
                for oid in oids {
                    encoder.write_opaque(oid)?;
                }
            },
        }
        Ok(())
    }

    fn decode_from(decoder: &mut Decoder<'_>, limits: GssLimits) -> Result<Self, DecodeError> {
        match decoder.read_u32()? {
            0 => Ok(Self::Ok),
            1 => Ok(Self::PrefixNotSupported(decoder.read_array(
                "RPCSEC_GSS channel-prefix preferences",
                limits.max_preference_count,
                |decoder| decoder.read_opaque("RPCSEC_GSS channel prefix", limits.max_channel_prefix_bytes),
            )?)),
            2 => Ok(Self::HashNotSupported(decoder.read_array(
                "RPCSEC_GSS channel-hash preferences",
                limits.max_preference_count,
                |decoder| decoder.read_opaque("RPCSEC_GSS channel hash OID", limits.max_oid_bytes),
            )?)),
            value => Err(DecodeError::InvalidDiscriminant {
                kind: "RPCSEC_GSS channel-binding status",
                value,
            }),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelBindingVerifierResult {
    pub status: ChannelBindingStatus,
    pub mic: Vec<u8>,
}

impl ChannelBindingVerifierResult {
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut encoder = Encoder::new();
        self.status.encode_into(&mut encoder)?;
        encoder.write_opaque(&self.mic)?;
        Ok(encoder.into_bytes())
    }

    pub fn decode(input: &[u8], limits: GssLimits) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(input);
        let status = ChannelBindingStatus::decode_from(&mut decoder, limits)?;
        let mic = decoder.read_opaque("RPCSEC_GSS channel-binding reply MIC", limits.max_mic_bytes)?;
        decoder.finish()?;
        Ok(Self { status, mic })
    }
}

pub fn encode_channel_binding_mic_in_args(hash: &[u8]) -> Result<Vec<u8>, EncodeError> {
    let mut encoder = Encoder::new();
    encoder.write_opaque(hash)?;
    Ok(encoder.into_bytes())
}

pub fn encode_channel_binding_mic_in_result(
    sequence: u32,
    hash: &[u8],
    status: &ChannelBindingStatus,
) -> Result<Vec<u8>, EncodeError> {
    let mut encoder = Encoder::new();
    encoder.write_u32(sequence);
    encoder.write_opaque(hash)?;
    status.encode_into(&mut encoder)?;
    Ok(encoder.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_round_trip_and_v2_validation() {
        let credential = Credential {
            version: Version::V2,
            procedure: Procedure::BindChannel,
            sequence: 9,
            service: Service::None,
            handle: vec![1, 2, 3],
        };
        assert_eq!(Credential::decode(&credential.encode().unwrap(), GssLimits::default()).unwrap(), credential);
    }

    #[test]
    fn rejects_v2_features_in_v1_credentials() {
        let credential = Credential {
            version: Version::V1,
            procedure: Procedure::BindChannel,
            sequence: 1,
            service: Service::None,
            handle: vec![1],
        };
        assert!(Credential::decode(&credential.encode().unwrap(), GssLimits::default()).is_err());
    }

    #[test]
    fn integrity_body_exposes_embedded_sequence_without_copying_payload() {
        let body = IntegrityBody {
            protected: [7u32.to_be_bytes().as_slice(), b"arguments"].concat(),
            checksum: vec![9; 16],
        };
        let encoded = body.encode().unwrap();
        let decoded = IntegrityBody::decode(&encoded, GssLimits::default()).unwrap();
        assert_eq!(decoded.embedded_sequence().unwrap(), 7);
        assert_eq!(decoded.procedure_body().unwrap(), b"arguments");
    }

    #[test]
    fn channel_binding_verifiers_round_trip() {
        let arguments = ChannelBindingVerifierArgs {
            prefix: b"tls-exporter".to_vec(),
            hash_oid: vec![0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
            mic: vec![7; 32],
        };
        assert_eq!(
            ChannelBindingVerifierArgs::decode(&arguments.encode().unwrap(), GssLimits::default()).unwrap(),
            arguments
        );

        let result = ChannelBindingVerifierResult {
            status: ChannelBindingStatus::HashNotSupported(vec![vec![1, 2, 3]]),
            mic: vec![9; 32],
        };
        assert_eq!(
            ChannelBindingVerifierResult::decode(&result.encode().unwrap(), GssLimits::default()).unwrap(),
            result
        );
    }
}
