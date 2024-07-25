use kernel_model_lib::{
    AbstractState, Command, Commander, Error, ExecutionResult, Interval, Printer, TestPort,
    ValueList,
};
use lazy_static::lazy_static;
use libafl_qemu::{sys::CPUArchStatePtr, Qemu};
use model_mem::{
    read_sv39_page_table, read_sv48_page_table, read_sv57_page_table, segment_vpages, MappingFlags,
    MemRandCommander, ReadMem, UserSpace, UserSpaceConfig,
};
use std::{env, sync::Mutex, usize};

/// Test port communicating with RCore
struct RCoreTestPort;

impl TestPort<UserSpace> for RCoreTestPort {
    fn send(&mut self, command: &dyn Command<UserSpace>) -> Result<(), Error> {
        let command_str = command.stringify();
        // Write 4 + n format
        write_to_rcore_mem(
            RCORE_CMD_BUF_VADDR,
            (command_str.len() as u32).to_le_bytes().as_slice(),
        );
        write_to_rcore_mem(RCORE_CMD_BUF_VADDR + 4, command_str.as_bytes());
        Ok(())
    }

    fn receive_retv(&mut self) -> ExecutionResult {
        let mut retv = [0u8; 8];
        read_from_rcore_mem(RCORE_RET_VADDR, &mut retv);
        Ok(usize::from_le_bytes(retv))
    }

    fn receive_state(&mut self) -> Result<&UserSpace, Error> {
        unreachable!();
    }
}

/// Virtual address of RCore command buffer.
const RCORE_CMD_BUF_VADDR: u64 = 0x16000;

/// Virtual address of RCore return value.
const RCORE_RET_VADDR: u64 = RCORE_CMD_BUF_VADDR + 4096;

/// Write some data to rcore's virtual memory.
fn write_to_rcore_mem(vaddr: u64, buf: &[u8]) {
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

/// Read some data from rcore's virtual memory.
fn read_from_rcore_mem(vaddr: u64, buf: &mut [u8]) {
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

/// Stdout printer.
struct StdoutPrinter;

impl Printer<UserSpace> for StdoutPrinter {
    fn print_str(&mut self, s: &str) -> Result<(), Error> {
        println!("{}", s);
        Ok(())
    }
    fn print_state(&mut self, s: &UserSpace) -> Result<(), Error> {
        for seg in s.segments.iter() {
            println!("[{:#x}~{:#x}] {:?}", seg.left, seg.right, seg.value);
        }
        Ok(())
    }
}

lazy_static!(
    /// Kernel memory state.
    static ref KERNEL_STATE: Mutex<UserSpace> = Mutex::new(UserSpace::default());
    /// Model memory state.
    static ref MODEL_STATE: Mutex<UserSpace> = Mutex::new(UserSpace::new(UserSpaceConfig {
        ustart: 0,
        text_rodata_sep: 0,
        rodata_rwdata_sep: 0,
        heap_bottom: 0x1a000,
        heap_top: 0x1d000,
        uend: 0,
        page_size: 4096,
        max_heap_size: 0x100000000,
    }));
);

/// Random commander.
static mut COMMANDER: MemRandCommander = MemRandCommander {
    brk: true,
    mmap: false,
    munmap: false,
    brk_addr_range: (0x1b000, 0x29000),
    mmap_addr_range: (0, 0),
    mmap_len_range: (0, 0),
};

/// RCore test port.
static mut TEST_PORT: RCoreTestPort = RCoreTestPort;

/// Stdout printer.
static mut PRINTER: StdoutPrinter = StdoutPrinter;

/// Return value of command.
static mut MODEL_RETV: isize = 0;

/// Execute step.
#[derive(Debug, Clone, Copy)]
enum Step {
    Init,
    Command,
    Check,
}

/// Current step
static mut STEP: Step = Step::Init;

/// 1. Init model state
fn init(satp: u64) {
    MODEL_STATE.lock().unwrap().segments = ValueList(read_page_table(satp));
}

/// 1. Commander generate command.
/// 2. Test port send write command to kernel buffer.
/// 3. Execute command on model state.
fn command() {
    unsafe {
        let command = COMMANDER.command().unwrap();
        TEST_PORT.send(command.as_ref()).unwrap();
        MODEL_RETV = command
            .execute(&mut MODEL_STATE.lock().unwrap())
            .map_or(-1, |x| x as isize);
    }
}

/// 1. Get return value of command.
/// 2. Check return value.
/// 3. Get memory state from kernel.
/// 4. Check memory state.
fn check(satp: u64) {
    unsafe {
        let kernel_retv = TEST_PORT.receive_retv().unwrap() as isize;
        if kernel_retv != MODEL_RETV {
            println!("Return value mismatch: {} != {}", kernel_retv, MODEL_RETV);
        }
        let mut kernel_state = UserSpace::default();
        kernel_state.segments = ValueList(read_page_table(satp));
        if !kernel_state.matches(&MODEL_STATE.lock().unwrap()) {
            println!("Memory state mismatch");
            println!("Kernel state:");
            PRINTER.print_state(&kernel_state).unwrap();
            println!("Model state:");
            PRINTER.print_state(&MODEL_STATE.lock().unwrap()).unwrap();
            panic!("Check failed!");
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
        8 => read_sv39_page_table(root_addr, &MemoryReader),
        9 => read_sv48_page_table(root_addr, &MemoryReader),
        10 => read_sv57_page_table(root_addr, &MemoryReader),
        _ => panic!("Unsupported mode: {}", mode),
    };
    segment_vpages(&pages)
}

extern "C" fn hook(_data: u64, ptr: CPUArchStatePtr, _addr: u64) {
    match unsafe { STEP } {
        Step::Init => {
            let satp: u64 = unsafe { ptr.as_ref().expect("CPUArchStatePtr is null").satp };
            init(satp);
            unsafe {
                STEP = Step::Command;
            }
        }
        Step::Command => {
            command();
            unsafe {
                STEP = Step::Check;
            }
        }
        Step::Check => {
            let satp: u64 = unsafe { ptr.as_ref().expect("CPUArchStatePtr is null").satp };
            check(satp);
            unsafe {
                STEP = Step::Command;
            }
        }
    }
}

/// Physical memory reader for QEMU.
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
