use crate::{
    traits::{Marshall, UnMarshall},
    ReturnCode,
};
use std::convert::TryInto;
use tss_esapi_sys::_PRIVATE;

buffer_type!(Private, ::std::mem::size_of::<_PRIVATE>(), TPM2B_PRIVATE);

impl Marshall for Private {
    const BUFFER_SIZE: usize = std::mem::size_of::<TPM2B_PRIVATE>();

    /// Produce a marshalled [`TPM2B_PRIVATE`]
    fn marshall(&self) -> Result<Vec<u8>> {
        let mut buffer = vec![0; Self::BUFFER_SIZE];
        let mut offset = 0;

        ReturnCode::ensure_success(
            unsafe {
                crate::tss2_esys::Tss2_MU_TPM2B_PRIVATE_Marshal(
                    &self.clone().try_into().map_err(|e| {
                        error!("Failed to convert Private to TPM2B_PRIVATE: {}", e);
                        Error::local_error(WrapperErrorKind::InvalidParam)
                    })?,
                    buffer.as_mut_ptr(),
                    Self::BUFFER_SIZE.try_into().map_err(|e| {
                        error!("Failed to convert size of buffer to TSS size_t type: {}", e);
                        Error::local_error(WrapperErrorKind::InvalidParam)
                    })?,
                    &mut offset,
                )
            },
            |ret| {
                error!("Failed to marshal Private: {}", ret);
            },
        )?;

        let checked_offset = usize::try_from(offset).map_err(|e| {
            error!("Failed to parse offset as usize: {}", e);
            Error::local_error(WrapperErrorKind::InvalidParam)
        })?;
        buffer.truncate(checked_offset);
        Ok(buffer)
    }
}

impl UnMarshall for Private {
    /// Unmarshall the structure from [`TPM2B_PRIVATE`]
    fn unmarshall(marshalled_data: &[u8]) -> Result<Self> {
        let mut dest = TPM2B_PRIVATE::default();
        let mut offset = 0;

        ReturnCode::ensure_success(
            unsafe {
                crate::tss2_esys::Tss2_MU_TPM2B_PRIVATE_Unmarshal(
                    marshalled_data.as_ptr(),
                    marshalled_data.len().try_into().map_err(|e| {
                        error!("Failed to convert length of marshalled data: {}", e);
                        Error::local_error(WrapperErrorKind::InvalidParam)
                    })?,
                    &mut offset,
                    &mut dest,
                )
            },
            |ret| error!("Failed to unmarshal Private: {}", ret),
        )?;

        Private::try_from(dest)
    }
}
