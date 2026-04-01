use common::{crypt, generate_key};
use std::fs;

const CAVE_PATTERN: u8 = 0xCC;
const SIZE_PLACEHOLDER: usize = 0xDEADBEEF;

fn find_pattern(data: &[u8], repeat_count: usize) -> Option<usize> {
    let mut consecutive = 0;

    for (i, &b) in data.iter().enumerate() {
        if b == CAVE_PATTERN {
            consecutive += 1;
            if consecutive >= repeat_count {
                return Some(i - repeat_count + 1);
            }
        } else {
            consecutive = 0;
        }
    }
    None
}

//Rust way to search for a sequence of bytes inside a larger array
fn find_bytes_offset(data: &[u8], target_sequence: &[u8]) -> Option<usize> {
    data.windows(target_sequence.len())
        .position(|window| window == target_sequence)
}

fn main() {
    println!("TL Packer started.");

    let stub_path = "target/release/stub.exe";
    let target_payload = "target/release/payload.exe";
    let out_file = "target/release/packed.exe";

    println!("Read the stub file.");
    let mut stub_bytes = fs::read(stub_path).expect("Cant read stub file...");

    println!("Read the target file.");
    let mut payload_bytes = fs::read(target_payload).expect("Cant read payload file...");

    let key = generate_key();
    println!("Time key generated {}.", key);

    crypt(&mut payload_bytes, key);

    let offset = find_pattern(&stub_bytes, 20).expect("Cant find stub pattern.");
    print!("Stub offset {}", offset);

    //overwrite with payload
    for (i, byte) in payload_bytes.iter().enumerate() {
        stub_bytes[offset + i] = *byte;
    }

    let fpointer_size = SIZE_PLACEHOLDER.to_le_bytes();

    let size_offset =
        find_bytes_offset(&stub_bytes, &fpointer_size).expect("Could not find size placeholder!");

    println!("Found Size Variable at offset: 0x{:X}", size_offset);
    let actual_size_bytes = payload_bytes.len().to_le_bytes(); //LE

    for (i, byte) in actual_size_bytes.iter().enumerate() {
        stub_bytes[size_offset + i] = *byte;
    }

    fs::write(out_file, stub_bytes).expect("Error writing out file.");
    println!("Saved packed file to: {}", out_file);
}
