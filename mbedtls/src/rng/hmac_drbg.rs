/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use mbedtls_sys::types::raw_types::{c_int, c_uchar, c_void};
use mbedtls_sys::types::size_t;
pub use mbedtls_sys::HMAC_DRBG_RESEED_INTERVAL as RESEED_INTERVAL;
use mbedtls_sys::*;

use crate::rng::{EntropyCallback, RngCallback, RngCallbackMut};
use crate::error::{IntoResult, Result};
use crate::hash::MdInfo;
use std::sync::Arc;

#[allow(dead_code)]
pub struct HmacDrbg {
    // Moving data causes dangling pointers: https://github.com/ARMmbed/mbedtls/issues/2147
    // Storing data in heap and forcing rust move to only move the pointer (box) referencing it.
    // The move will be faster. Access to data will be slower due to additional indirection.
    inner: hmac_drbg_context,
    entropy: Option<Arc<dyn EntropyCallback + 'static>>,
}

unsafe impl Send for HmacDrbg {}

#[cfg(feature = "threading")]
unsafe impl Sync for HmacDrbg {}

#[allow(dead_code)]
impl Drop for HmacDrbg {
    fn drop(&mut self) {
        unsafe { hmac_drbg_free(&mut self.inner) };
    }
}

impl HmacDrbg {
    pub fn new<T: EntropyCallback + Send + Sync + 'static>(
        md_info: MdInfo,
        entropy: Arc<T>,
        additional_entropy: Option<&[u8]>,
    ) -> Result<HmacDrbg> {

        let mut ret = HmacDrbg {
            inner: hmac_drbg_context::default(),
            entropy: Some(entropy),
        };
        
        unsafe {
            hmac_drbg_init(&mut ret.inner);
            hmac_drbg_seed(
                &mut ret.inner,
                md_info.into(),
                Some(T::call),
                ret.entropy.as_ref().unwrap().data_ptr(),
                additional_entropy.map(<[_]>::as_ptr).unwrap_or(::core::ptr::null()),
                additional_entropy.map(<[_]>::len).unwrap_or(0)
            )
            .into_result()?
        };
        Ok(ret)
    }

    
    pub fn from_buf(md_info: MdInfo, entropy: &[u8]) -> Result<HmacDrbg> {
        let mut ret = HmacDrbg {
            inner: hmac_drbg_context::default(),
            entropy: None,
        };

        unsafe {
            hmac_drbg_init(&mut ret.inner);
            hmac_drbg_seed_buf(
                &mut ret.inner,
                md_info.into(),
                entropy.as_ptr(),
                entropy.len()
            )
            .into_result()?
        };
        Ok(ret)
    }

    pub fn prediction_resistance(&self) -> bool {
        if self.inner.prediction_resistance == HMAC_DRBG_PR_OFF {
            false
        } else {
            true
        }
    }

    pub fn set_prediction_resistance(&mut self, pr: bool) {
        unsafe {
            hmac_drbg_set_prediction_resistance(
                &mut self.inner,
                if pr {
                    HMAC_DRBG_PR_ON
                } else {
                    HMAC_DRBG_PR_OFF
                },
            )
        }
    }

    pub fn entropy_len(&self) -> size_t {
        self.inner.entropy_len
    }

    pub fn set_entropy_len(&mut self, len: size_t) {
        unsafe { hmac_drbg_set_entropy_len(&mut self.inner, len); }
    }

    pub fn reseed_interval(&self) -> c_int {
        self.inner.reseed_interval
    }

    pub fn set_reseed_interval(&mut self, i: c_int) {
        unsafe { hmac_drbg_set_reseed_interval(&mut self.inner, i); }
    }

    pub fn reseed(&mut self, additional_entropy: Option<&[u8]>) -> Result<()> {
        unsafe {
            hmac_drbg_reseed(
                &mut self.inner,
                additional_entropy
                    .map(<[_]>::as_ptr)
                    .unwrap_or(::core::ptr::null()),
                additional_entropy.map(<[_]>::len).unwrap_or(0)
            )
            .into_result()?
        };
        Ok(())
    }

    pub fn update(&mut self, entropy: &[u8]) {
        unsafe { hmac_drbg_update(&mut self.inner, entropy.as_ptr(), entropy.len()) };
    }

    // TODO:
    //
    // hmac_drbg_random_with_add
    // hmac_drbg_write_seed_file
    // hmac_drbg_update_seed_file
    //
}

impl RngCallbackMut for HmacDrbg {
    #[inline(always)]
    unsafe extern "C" fn call_mut(user_data: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int {
        // Mutex used in hmac_drbg_random: ../../../mbedtls-sys/vendor/crypto/library/hmac_drbg.c:363
        hmac_drbg_random(user_data, data, len)
    }

    fn data_ptr_mut(&mut self) -> *mut c_void {
        &self.inner as *const _ as *mut _
    }
}

impl RngCallback for HmacDrbg {
    #[inline(always)]
    unsafe extern "C" fn call(user_data: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int {
        // Mutex used in hmac_drbg_random: ../../../mbedtls-sys/vendor/crypto/library/hmac_drbg.c:363
        hmac_drbg_random(user_data, data, len)
    }

    fn data_ptr(&self) -> *mut c_void {
        &self.inner as *const _ as *mut _
    }
}
