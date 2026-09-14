//! SHA-256 compression accelerated by the SP1 zkVM `sha256` precompiles.

unsafe extern "C" {
    fn syscall_sha256_extend(w: *mut [u64; 64]);
    fn syscall_sha256_compress(w: *mut [u64; 64], state: *mut [u64; 8]);
}

#[inline(always)]
pub(super) fn compress(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
    unsafe {
        #[repr(align(64))]
        struct W([u64; 64]);

        let mut w = W([0u64; 64]);
        let mut state_u64 = [0u64; 8];

        if blocks.is_empty() {
            return;
        }

        let first_block_aligned = blocks[0].as_ptr() as usize & 7 == 0;

        if first_block_aligned {
            for block in blocks {
                let src = block.as_ptr() as *const u64;
                for i in 0..8 {
                    let val = *src.add(i);
                    let b0 = val & 0xFF;
                    let b1 = (val >> 8) & 0xFF;
                    let b2 = (val >> 16) & 0xFF;
                    let b3 = (val >> 24) & 0xFF;
                    let b4 = (val >> 32) & 0xFF;
                    let b5 = (val >> 40) & 0xFF;
                    let b6 = (val >> 48) & 0xFF;
                    let b7 = (val >> 56) & 0xFF;
                    w.0[i * 2] = (b0 << 24) + (b1 << 16) + (b2 << 8) + b3;
                    w.0[i * 2 + 1] = (b4 << 24) + (b5 << 16) + (b6 << 8) + b7;
                }

                for (dst, src) in state_u64.iter_mut().zip(state.iter()) {
                    *dst = *src as u64;
                }

                syscall_sha256_extend(&mut w.0);
                syscall_sha256_compress(&mut w.0, &mut state_u64);

                for (dst, src) in state.iter_mut().zip(state_u64.iter()) {
                    *dst = *src as u32;
                }
            }
        } else {
            for block in blocks {
                let src = block.as_ptr();
                for i in 0..16 {
                    w.0[i] = u32::from_be_bytes([
                        *src.add(i * 4),
                        *src.add(i * 4 + 1),
                        *src.add(i * 4 + 2),
                        *src.add(i * 4 + 3),
                    ]) as u64;
                }

                for (dst, src) in state_u64.iter_mut().zip(state.iter()) {
                    *dst = *src as u64;
                }

                syscall_sha256_extend(&mut w.0);
                syscall_sha256_compress(&mut w.0, &mut state_u64);

                for (dst, src) in state.iter_mut().zip(state_u64.iter()) {
                    *dst = *src as u32;
                }
            }
        }
    }
}
