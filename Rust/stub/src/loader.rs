use core::ptr;
use windows_sys::Win32::System::Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc,
};
use windows_sys::Win32::System::SystemServices::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE,
};

//For ptr::copy_nonoverlapping(intrinsic function) the Rust compilier optimises
// by using C std library function which is removed by /NODEFAULTLIB...hence the linker fails
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        unsafe {
            *dest.add(i) = *src.add(i);
            i += 1;
        }
    }
    dest
}

pub fn load_memory_and_execute(payload: &[u8]) {
    let dos_header = payload.as_ptr() as *const IMAGE_DOS_HEADER;

    if (unsafe { *dos_header }).e_magic != IMAGE_DOS_SIGNATURE {
        return;
    }

    let nt_offset = (unsafe { *dos_header }).e_lfanew as usize;
    let nt_headers = unsafe { payload.as_ptr().add(nt_offset) } as *const IMAGE_NT_HEADERS64;

    if (unsafe { *nt_headers }).Signature != IMAGE_NT_SIGNATURE {
        return;
    }

    //get the image size and allocate rwx memory...malware would change it back.
    let image_size = (unsafe { *nt_headers }).OptionalHeader.SizeOfImage as usize;
    let image_base = unsafe {
        VirtualAlloc(
            ptr::null_mut(),
            image_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };

    if image_base.is_null() {
        return;
    };

    //copy sections:
    let section_header_ptr = (nt_headers as usize + core::mem::size_of::<IMAGE_NT_HEADERS64>())
        as *const IMAGE_SECTION_HEADER;

    let number_of_sections = (unsafe { *nt_headers }).FileHeader.NumberOfSections;

    for i in 0..number_of_sections {
        let section = unsafe { &*section_header_ptr.add(i as usize) };

        if section.SizeOfRawData > 0 {
            let dest = unsafe { (image_base as *mut u8).add(section.VirtualAddress as usize) };
            let src = unsafe { payload.as_ptr().add(section.PointerToRawData as usize) };
            unsafe { ptr::copy_nonoverlapping(src, dest, section.SizeOfRawData as usize) };
        }
    }

    //Base Relocations and Import Resolution are way too complex for a learning project...
    // Base relocations would involves patching all the addresses to what VirtualAlloc returned.
    // Import Resolution requires fixing up the IAT table with the addresses of requisite functions e.g. user32::MessageBox
    // The simple solution is to have an "independent" payload... use C with assembly.

    // Calculate the absolute address of the entry point
    let entry_point_rva = unsafe { (*nt_headers).OptionalHeader.AddressOfEntryPoint };
    let entry_point_address = (image_base as usize) + (entry_point_rva as usize);

    let entry_fn: extern "system" fn() = unsafe { core::mem::transmute(entry_point_address) };
    entry_fn();
}
