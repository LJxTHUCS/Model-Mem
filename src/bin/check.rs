use kernel_model_lib::{
    CheckLevel, Command, Error, Interval, Printer, Runner, TestPort, ValueList,
};
use lazy_static::lazy_static;
use libafl_qemu::{sys::CPUArchStatePtr, Qemu};
use model_mem::{
    read_sv39_page_table, read_sv48_page_table, read_sv57_page_table, segment_vpages, MappingFlags,
    MemRandCommander, ReadMem, UserSpace, UserSpaceConfig,
};
use std::{env, sync::Mutex};

/// Test port communicating with target kernel
struct MemTestPort;

impl TestPort<UserSpace> for MemTestPort {
    fn send_command(&mut self, command: &dyn Command<UserSpace>) -> Result<(), Error> {
        let command_bytes = command.serialize();
        // Write 4 + n format
        write_to_target_mem(
            CMD_BUF_VADDR,
            (command_bytes.len() as u32).to_le_bytes().as_slice(),
        );
        write_to_target_mem(CMD_BUF_VADDR + 4, &command_bytes);
        Ok(())
    }
    fn get_retv(&mut self) -> isize {
        let mut retv = [0u8; 8];
        read_from_target_mem(RETV_VADDR, &mut retv);
        isize::from_le_bytes(retv)
    }
    fn get_state(&mut self) -> Result<UserSpace, Error> {
        let mut state = UserSpace::default();
        state.segments = ValueList(read_page_table(unsafe { SATP }));
        Ok(state)
    }
}

/// Stdout printer.
struct StdoutPrinter;

impl Printer<UserSpace> for StdoutPrinter {
    fn print_str(&mut self, s: &str) {
        println!("{}", s);
    }
    fn print_state(&mut self, s: &UserSpace) {
        for seg in s.segments.iter() {
            println!("[{:#x}~{:#x}] {:?}", seg.left, seg.right, seg.value);
        }
    }
}

/// Virtual address of target command buffer.
const CMD_BUF_VADDR: u64 = 0x13000;

/// Virtual address of target return value.
const RETV_VADDR: u64 = CMD_BUF_VADDR + 4096;

static mut SATP: u64 = 0;

/// Write some data to target's virtual memory.
fn write_to_target_mem(vaddr: u64, buf: &[u8]) {
    let cpu_ptr = unsafe { libafl_qemu::sys::libafl_qemu_get_cpu(0) };
    // Write data
    unsafe {
        libafl_qemu::sys::cpu_memory_rw_debug(
            cpu_ptr,
            vaddr,
            buf.as_ptr() as *mut _,
            buf.len(),
            true,
        );
    }
}

/// Read some data from target's virtual memory.
fn read_from_target_mem(vaddr: u64, buf: &mut [u8]) {
    let cpu_ptr = unsafe { libafl_qemu::sys::libafl_qemu_get_cpu(0) };
    // Read data
    unsafe {
        libafl_qemu::sys::cpu_memory_rw_debug(
            cpu_ptr,
            vaddr,
            buf.as_mut_ptr() as *mut _,
            buf.len(),
            false,
        );
    }
}

/// Physical memory reader for QEMU.
struct PhysMemoryReader;

impl ReadMem for PhysMemoryReader {
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

/// Read user space page table.
fn read_page_table(satp: u64) -> Vec<Interval<MappingFlags>> {
    const MASK: u64 = 0x0fff_ffff_ffff;
    const PAGE_SIZE: u64 = 4096;
    let root_addr = (satp & MASK) * PAGE_SIZE;
    let mode = satp >> 60;
    let pages = match mode {
        8 => read_sv39_page_table(root_addr, &PhysMemoryReader),
        9 => read_sv48_page_table(root_addr, &PhysMemoryReader),
        10 => read_sv57_page_table(root_addr, &PhysMemoryReader),
        _ => panic!("Unsupported mode: {}", mode),
    };
    segment_vpages(&pages)
}

lazy_static!(
    /// Kernel memory state.
    static ref RUNNER: Mutex<Runner<MemRandCommander, StdoutPrinter, MemTestPort, UserSpace>> =
    Mutex::new(Runner::new(MemRandCommander {
        brk: false,
        sbrk: true,
        mmap: false,
        munmap: false,
        brk_addr_range: (0x1b000, 0x29000),
        sbrk_incr_range: (0, 0x2000),
        mmap_addr_range: (0, 0),
        mmap_len_range: (0, 0),
    }, StdoutPrinter, MemTestPort, UserSpace::new(UserSpaceConfig{
        ustart: 0,
        text_rodata_sep: 0,
        rodata_rwdata_sep: 0,
        heap_bottom: 0x19000,
        heap_top: 0x19000,
        uend: 0,
        page_size: 4096,
        max_heap_size: 0x100000000,
    })));
);

extern "C" fn hook(_data: u64, ptr: CPUArchStatePtr, _addr: u64) {
    unsafe {
        SATP = ptr.as_ref().unwrap().satp;
        RUNNER
            .lock()
            .unwrap()
            .step(CheckLevel::Relaxed, CheckLevel::Strict)
            .expect("Check failed");
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
