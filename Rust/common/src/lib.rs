#![no_std]

use core::arch::x86_64::{__cpuid, _rdtsc};

#[inline(always)]
fn timing_calculation() -> u64 {
    unsafe {
        let start = _rdtsc();

        // The "Heavy" Loop
        for _ in 0..25_000 {
            // After various attemps WinDbg was just too fast... __cpuid solves this by forcing CPU to finish tasks
            let _ = __cpuid(0);
        }

        let end = _rdtsc();
        end - start
    }
}

#[inline(never)]
pub fn get_current_bucket() -> u64 {
    // cache...
    let _ = timing_calculation();
    let cycles = timing_calculation();
    cycles / 500_000
}

#[inline(always)]
pub fn key_from_bucket(bucket: u64) -> u64 {
    bucket.wrapping_mul(0x5EED_C0DE_1234_5678) ^ 0xAABB_CCDD_EEFF_0011 //make it a very random number
}

// the key given back will be in a bucket as dicatated by the cycles divisor...
#[inline(never)]
pub fn generate_key() -> u64 {
    let bucket = get_current_bucket();
    key_from_bucket(bucket)
}

struct XorShift {
    value: u64,
}

impl XorShift {
    fn new(seed: u64) -> Self {
        Self { value: seed }
    }

    fn shift(&mut self) -> u8 {
        let mut x = self.value;
        //standard shift values
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;

        self.value = x;

        (x & 0xFF) as u8
    }
}

pub fn crypt(buffer: &mut [u8], key: u64) {
    let mut rng = XorShift::new(key);

    for byte in buffer.iter_mut() {
        let mask = rng.shift();
        *byte ^= mask;
    }
}
