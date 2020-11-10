// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::constants::tags::StructureTag;
use crate::interface_types::resource_handles::Hierarchy;
use crate::tss2_esys::{TPM2B_DIGEST, TPMT_TK_HASHCHECK, TPMT_TK_VERIFIED};
use crate::{Error, Result, WrapperErrorKind};
use log::error;
use std::convert::{TryFrom, TryInto};

/// Macro used for implementing try_from
/// TssTicketType -> TicketType
/// TicketType -> TssTicketType
const TPM2B_DIGEST_BUFFER_SIZE: usize = 64;
macro_rules! impl_ticket_try_froms {
    ($ticket_type:ident, $tss_ticket_type:ident) => {
        impl TryFrom<$ticket_type> for $tss_ticket_type {
            type Error = Error;
            fn try_from(ticket: $ticket_type) -> Result<Self> {
                let digest = ticket.digest;
                if digest.len() > TPM2B_DIGEST_BUFFER_SIZE {
                    return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
                }
                let mut buffer = [0; TPM2B_DIGEST_BUFFER_SIZE];
                buffer[..digest.len()].clone_from_slice(&digest[..digest.len()]);
                Ok($tss_ticket_type {
                    tag: <$ticket_type>::TAG.into(),
                    hierarchy: ticket.hierarchy.rh(),
                    digest: TPM2B_DIGEST {
                        size: digest.len().try_into().unwrap(), // should not fail based on the checks done above
                        buffer,
                    },
                })
            }
        }

        impl TryFrom<$tss_ticket_type> for $ticket_type {
            type Error = Error;

            fn try_from(tss_ticket: $tss_ticket_type) -> Result<Self> {
                match StructureTag::try_from(tss_ticket.tag) {
                    Ok(val) => {
                        if val != <$ticket_type>::TAG {
                            return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
                        }
                    }
                    Err(why) => {
                        error!("Failed to parsed tag: {}", why);
                        return Err(Error::local_error(WrapperErrorKind::InvalidParam));
                    }
                };

                let len = tss_ticket.digest.size.into();
                if len > TPM2B_DIGEST_BUFFER_SIZE {
                    error!(
                        "Error: Invalid digest size.(Digest size: {0} > Digest buffer size: {1})",
                        len, TPM2B_DIGEST_BUFFER_SIZE,
                    );
                    return Err(Error::local_error(WrapperErrorKind::InvalidParam));
                }
                let mut digest = tss_ticket.digest.buffer.to_vec();
                digest.truncate(len);

                let hierarchy = tss_ticket.hierarchy.try_into()?;

                Ok($ticket_type { hierarchy, digest })
            }
        }
    };
}

pub trait Ticket {
    const TAG: StructureTag;
    fn hierarchy(&self) -> Hierarchy;
    fn digest(&self) -> &[u8];
}

#[derive(Debug, Clone)]
pub struct HashcheckTicket {
    hierarchy: Hierarchy,
    digest: Vec<u8>,
}

impl Ticket for HashcheckTicket {
    /// The tag of the verified ticket.
    const TAG: StructureTag = StructureTag::Hashcheck;
    /// Get the hierarchy associated with the verification ticket.
    fn hierarchy(&self) -> Hierarchy {
        self.hierarchy
    }

    /// Get the digest associated with the verification ticket.
    fn digest(&self) -> &[u8] {
        &self.digest
    }
}

impl_ticket_try_froms!(HashcheckTicket, TPMT_TK_HASHCHECK);

/// Rust native wrapper for `TPMT_TK_VERIFIED` objects.
#[derive(Debug)]
pub struct VerifiedTicket {
    hierarchy: Hierarchy,
    digest: Vec<u8>,
}

impl Ticket for VerifiedTicket {
    // type TssTicketType = TPMT_TK_VERIFIED;
    /// The tag of the verified ticket.
    const TAG: StructureTag = StructureTag::Verified;
    /// Get the hierarchy associated with the verification ticket.
    fn hierarchy(&self) -> Hierarchy {
        self.hierarchy
    }
    /// Get the digest associated with the verification ticket.
    fn digest(&self) -> &[u8] {
        &self.digest
    }
}

impl_ticket_try_froms!(VerifiedTicket, TPMT_TK_VERIFIED);
