use bitflags::bitflags;
use core::mem::size_of;
use km_checker::{AbstractState, Interval};

/// Riscv page size is 4KB;
const RV_PAGE_SIZE: usize = 4096;

bitflags! {
    /// Riscv page table entry flags for sv32, sv39, sv48 and sv57.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct RiscvPTEFlags: u8 {
        const VALID = 1 << 0;
        const READABLE = 1 << 1;
        const WRITABLE = 1 << 2;
        const EXECUTABLE = 1 << 3;
        const USER = 1 << 4;
        const GLOBAL = 1 << 5;
        const ACCESSED = 1 << 6;
        const DIRTY = 1 << 7;
    }
}

impl AbstractState for RiscvPTEFlags {
    fn matches(&self, other: &Self) -> bool {
        self.bits() == other.bits()
    }
    fn update(&mut self, other: &Self) {
        *self = *other
    }
}

/// Common Riscv page table entry trait, for sv32, sv39, sv48 and sv57.
trait RiscvPTE {
    /// PTE flags
    fn flags(&self) -> RiscvPTEFlags;
    /// Physical Page Number
    fn ppn(&self) -> u64;
    /// PTE valid bit
    fn valid(&self) -> bool {
        self.flags().contains(RiscvPTEFlags::VALID)
    }
    /// PTE with either read, write, or execute flag is considered a leaf.
    fn leaf(&self) -> bool {
        self.flags().intersects(
            RiscvPTEFlags::READABLE | RiscvPTEFlags::WRITABLE | RiscvPTEFlags::EXECUTABLE,
        )
    }
}

/// Riscv Sv39 page table entry.
///
/// Sv39 implementations support a 39-bit virtual address space,
/// divided into 4 KiB pages. The 27-bit VPN is translated into a
/// 44-bit PPN via a three-level page table, while the 12-bit page
/// offset is untranslated.
#[derive(Debug, Clone, Copy)]
struct Sv39PTE(pub u64);

impl RiscvPTE for Sv39PTE {
    /// PTE flags
    fn flags(&self) -> RiscvPTEFlags {
        RiscvPTEFlags::from_bits_truncate(self.0 as u8)
    }
    /// Physical Page Number
    fn ppn(&self) -> u64 {
        (self.0 >> 10) & 0xFFFFFFFFFFF
    }
}

/// Riscv Sv48 page table entry.
///
/// Sv48 implementations support a 48-bit virtual address space,
/// divided into 4 KiB pages. The 36-bit VPN is translated into a
/// 44-bit PPN via a four-level page table, while the 12-bit page
/// offset is untranslated.
#[derive(Debug, Clone, Copy)]
struct Sv48PTE(pub u64);

impl RiscvPTE for Sv48PTE {
    /// PTE flags
    fn flags(&self) -> RiscvPTEFlags {
        RiscvPTEFlags::from_bits_truncate(self.0 as u8)
    }
    /// Physical Page Number
    fn ppn(&self) -> u64 {
        (self.0 >> 10) & 0xFFFFFFFFFFFF
    }
}

/// Riscv Sv57 page table entry.
///
/// Sv57 implementations support a 57-bit virtual address space,
/// divided into 4 KiB pages. The 45-bit VPN is translated into a
/// 56-bit PPN via a five-level page table, while the 12-bit page
/// offset is untranslated.
#[derive(Debug, Clone, Copy)]
struct Sv57PTE(pub u64);

impl RiscvPTE for Sv57PTE {
    /// PTE flags
    fn flags(&self) -> RiscvPTEFlags {
        RiscvPTEFlags::from_bits_truncate(self.0 as u8)
    }
    /// Physical Page Number
    fn ppn(&self) -> u64 {
        (self.0 >> 10) & 0xFFFFFFFFFFFFFF
    }
}

/// A trait for generic mem reading.
pub trait ReadMem {
    /// Read memory from a physical address.
    fn read(&self, paddr: u64, buf: &mut [u8]);
}

/// Virtual page: a virtual page number and its mapping flags.
#[derive(Debug)]
pub struct VirtPage {
    vpn: u64,
    flags: RiscvPTEFlags,
}

/// Read Sv39 page table and collect all virtual pages into a vector
pub fn read_sv39_page_table<R>(root_addr: u64, reader: &R) -> Vec<VirtPage>
where
    R: ReadMem,
{
    let mut vpages = Vec::new();
    read_page_table_recursive(root_addr as *const Sv39PTE, reader, 0, 2, &mut vpages);
    vpages
}

/// Read Sv48 page table and collect all virtual pages into a vector
pub fn read_sv48_page_table<R>(root_addr: u64, reader: &R) -> Vec<VirtPage>
where
    R: ReadMem,
{
    let mut vpages = Vec::new();
    read_page_table_recursive(root_addr as *const Sv48PTE, reader, 0, 3, &mut vpages);
    vpages
}

/// Read Sv57 page table and collect all virtual pages into a vector
pub fn read_sv57_page_table<R>(root_addr: u64, reader: &R) -> Vec<VirtPage>
where
    R: ReadMem,
{
    let mut vpages = Vec::new();
    read_page_table_recursive(root_addr as *const Sv57PTE, reader, 0, 4, &mut vpages);
    vpages
}

/// Read page table recursively. Same logic shared by Sv39, Sv48 and Sv57.
fn read_page_table_recursive<T, R>(
    page: *const T,
    reader: &R,
    vpn: u64,
    level: u64,
    vpages: &mut Vec<VirtPage>,
) where
    T: RiscvPTE,
    R: ReadMem,
{
    let mut buf = [0u8; RV_PAGE_SIZE];
    reader.read(page as u64, &mut buf);
    let page = unsafe {
        core::slice::from_raw_parts(buf.as_ptr() as *const T, RV_PAGE_SIZE / size_of::<T>())
    };
    for (i, pte) in page.iter().enumerate() {
        if pte.valid() {
            // PTE is leaf <=> level == 0
            if pte.leaf() ^ (level == 0) {
                todo!();
            }
            let vpn = (vpn << 9) | i as u64;
            if level == 0 {
                // Leaf
                vpages.push(VirtPage {
                    vpn,
                    flags: pte.flags().into(),
                });
            } else {
                // Inner
                let next_page = pte.ppn() * RV_PAGE_SIZE as u64;
                read_page_table_recursive(next_page as *const T, reader, vpn, level - 1, vpages);
            }
        }
    }
}

fn mask_flags(flags: RiscvPTEFlags) -> RiscvPTEFlags {
    flags & !(RiscvPTEFlags::DIRTY | RiscvPTEFlags::ACCESSED)
}

/// Segment virtual pages into contiguous intervals.
///
/// Note: `vpages` read from page table is already sorted by VPN.
pub fn segment_vpages(vpages: &Vec<VirtPage>) -> Vec<Interval<RiscvPTEFlags>> {
    let mut intervals = Vec::new();
    let mut i = 0;
    while i < vpages.len() {
        let start = vpages[i].vpn;
        let flags = mask_flags(vpages[i].flags);
        let mut end = start + 1;
        // Continuous pages with the same flags
        while i < vpages.len() - 1
            && vpages[i + 1].vpn == end
            && mask_flags(vpages[i + 1].flags) == flags
        {
            end += 1;
            i += 1;
        }
        intervals.push(Interval::new(
            start as usize * RV_PAGE_SIZE,
            end as usize * RV_PAGE_SIZE,
            flags,
        ));
        i += 1;
    }
    intervals
}
