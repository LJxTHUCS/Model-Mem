use std::env;

use model_mem::{
    read_sv39_page_table, read_sv48_page_table, read_sv57_page_table, segment_vpages, ReadMem,
};

use libafl_qemu::{sys::CPUArchStatePtr, Qemu};

struct MemoryReader;

impl ReadMem for MemoryReader {
    fn read(&self, paddr: u64, buf: &mut [u8]) {
        unsafe {
            libafl_qemu::sys::cpu_physical_memory_rw(
                paddr,
                buf.as_mut_ptr() as *mut _,
                buf.len() as u64,
                false,
            );
        }
    }
}

extern "C" fn hook(_data: u64, ptr: CPUArchStatePtr, addr: u64) {
    println!("Hook at addr {:#x}", addr);
    let satp: u64 = unsafe { ptr.as_ref().expect("CPUArchStatePtr is null").satp };
    const MASK: u64 = 0x0fff_ffff_ffff;
    const PAGE_SIZE: u64 = 4096;
    let root_addr = (satp & MASK) * PAGE_SIZE;
    let mode = satp >> 60;
    let pages = match mode {
        8 => read_sv39_page_table(root_addr, &MemoryReader),
        9 => read_sv48_page_table(root_addr, &MemoryReader),
        10 => read_sv57_page_table(root_addr, &MemoryReader),
        _ => panic!("Unsupported mode: {}", mode),
    };
    let segments = segment_vpages(&pages);
    for seg in segments {
        println!("Segment: {:#x}~{:#x} {:?}", seg.left, seg.right, seg.value);
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let env: Vec<(String, String)> = env::vars().collect();
    println!("Args: {:?}", args);

    let qemu = Qemu::init(&args, &env).unwrap();
    qemu.add_backdoor_hook(0, hook);

    unsafe {
        match qemu.run() {
            Ok(m) => println!("End with {:?}", m),
            Err(e) => println!("Error when running: {:?}", e),
        }
    }
}
