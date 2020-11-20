/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use crate::error::{IntoResult, Result};
use crate::rng::EntropyCallback;
use mbedtls_sys::*;
use mbedtls_sys::types::raw_types::{c_int, c_uchar, c_void};
use mbedtls_sys::types::size_t;
use std::sync::Arc;

callback!(EntropySourceCallbackMut,EntropySourceCallback(data: *mut c_uchar, size: size_t, out: *mut size_t) -> c_int);

#[allow(dead_code)]
pub struct OsEntropy {
    // Moving data causes dangling pointers: https://github.com/ARMmbed/mbedtls/issues/2147
    // Storing data in heap and forcing rust move to only move the pointer (box) referencing it.
    // The move will be faster. Access to data will be slower due to additional indirection.
    inner: Box<entropy_context>,
    sources: Vec<Arc<dyn EntropySourceCallback + Send + Sync + 'static>>,
}

impl Into<*mut mbedtls_sys::entropy_context> for &mut OsEntropy {
    fn into(self) -> *mut mbedtls_sys::entropy_context {
        &mut *self.inner
    }
}

impl Into<*const mbedtls_sys::entropy_context> for &mut OsEntropy {
    fn into(self) -> *const mbedtls_sys::entropy_context {
        &*self.inner
    }
}

impl Into<*const mbedtls_sys::entropy_context> for &OsEntropy {
    fn into(self) -> *const mbedtls_sys::entropy_context {
        &*self.inner
    }
}


unsafe impl Send for OsEntropy {}

///
/// Class has interior mutability via function called 'call'.
/// That function has an internal mutex to guarantee thread safety.
///
/// The other potential conflict is a mutable reference changing class.
/// That is avoided by having any users of the callback hold an 'Arc' to this class.
/// Rust will then ensure that a mutable reference cannot be aquired if more then 1 Arc exists to the same class.
///
#[cfg(feature = "threading")]
unsafe impl Sync for OsEntropy {}

#[allow(dead_code)]
impl OsEntropy {
    
    pub fn new() -> Self {
        let mut inner = Box::new(entropy_context::default());

        unsafe {
            entropy_init(&mut *inner);
        };

        OsEntropy {
            inner,
            sources: vec![],
        }
    }

    pub fn add_source<F: EntropySourceCallback + Send + Sync + 'static>(
        &mut self,
        source: Arc<F>,
        threshold: size_t,
        strong: bool,
    ) -> Result<()> {
        unsafe {
            // add_source is guarded with internal mutex: mbedtls-sys/vendor/crypto/library/entropy.c:143
            // all sources are called at later points via 'entropy_gather_internal' which in turn is called with internal mutex locked.
            entropy_add_source(
                self.into(),
                Some(F::call),
                source.data_ptr(),
                threshold,
                if strong { ENTROPY_SOURCE_STRONG } else { ENTROPY_SOURCE_WEAK }
            )
            .into_result()?
        };

        // Rust ensures only one mutable reference is currently in use.
        self.sources.push(source);
        Ok(())
    }

    pub fn update_manual(&mut self, data: &[u8]) -> Result<()> {
        // function is guarded with internal mutex: mbedtls-sys/vendor/crypto/library/entropy.c:241
        unsafe { entropy_update_manual(self.into(), data.as_ptr(), data.len()) }.into_result()?;
        Ok(())
    }

    pub fn gather(&mut self) -> Result<()> {
        // function is guarded with internal mutex: mbedtls-sys/vendor/crypto/library/entropy.c:310
        unsafe { entropy_gather(self.into()) }.into_result()?;
        Ok(())
    }

}

#[allow(dead_code)]
impl Drop for OsEntropy {
    fn drop(&mut self) {
        unsafe { entropy_free(self.into()); }
    }
}


impl EntropyCallback for OsEntropy {
    #[inline(always)]
    unsafe extern "C" fn call(user_data: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int {
        // mutex used in entropy_func: ../../../mbedtls-sys/vendor/crypto/library/entropy.c:348
        // note: we're not using MBEDTLS_ENTROPY_NV_SEED so the initialization is not present or a race condition.
        entropy_func(user_data, data, len)
    }

    fn data_ptr(&self) -> *mut c_void {
        &*self.inner as *const _ as *mut _
    }
}
