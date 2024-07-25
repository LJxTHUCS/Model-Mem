use crate::linux_err;
use crate::MappingFlags;
use crate::UserSpace;
use bitflags::bitflags;
use kernel_model_lib::{Command, ExecutionResult, Interval, ValueList};

/// [`Brk`] change the location of the program break, which
/// defines the end of the process's data segment.
///
/// Ref: https://man7.org/linux/man-pages/man2/brk.2.html
#[derive(Debug)]
pub struct Brk {
    /// The new program break.
    pub addr: usize,
}

impl Command<UserSpace> for Brk {
    fn execute(&self, state: &mut UserSpace) -> ExecutionResult {
        // println!("addr: {:#x}", self.addr);
        // println!("heap_bottom: {:#x}", state.config.heap_bottom);
        // println!("heap_top: {:#x}", state.config.heap_top);
        // println!("max_heap_size: {:#x}", state.config.max_heap_size);
        if self.addr > state.config.heap_bottom
            && self.addr <= state.config.heap_bottom + state.config.max_heap_size
        {
            let addr = ceil(self.addr, state.config.page_size);
            for seg in state.segments.iter_mut() {
                if seg.left == state.config.heap_bottom {
                    seg.right = addr;
                    break;
                }
            }
            state.config.heap_top = addr;
            Ok(0)
        } else {
            Err(linux_err!(ENOMEM))
        }
    }
    fn stringify(&self) -> String {
        format!("brk({})", self.addr)
    }
}

/// [`Mmap`] creates a new mapping in the virtual address
/// space of the calling process.
///
/// Ref: https://man7.org/linux/man-pages/man2/mmap.2.html
#[derive(Debug)]
pub struct Mmap {
    /// The starting address of the mapping.
    pub addr: usize,
    /// The length of the mapping.
    pub len: usize,
    /// Memory protection of the mapping.
    pub prot: ProtFlags,
    /// Mapping flags
    pub flags: MmapFlags,
    // File-related fields
}

bitflags! {
    /// Generic page table entry flags that indicate the corresponding mapped
    /// memory region permissions and attributes.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ProtFlags: u8 {
        /// The memory is readable.
        const READ          = 1 << 0;
        /// The memory is writable.
        const WRITE         = 1 << 1;
        /// The memory is executable.
        const EXECUTE       = 1 << 2;
    }
}

impl ProtFlags {
    /// Read-only memory.
    pub const RO: Self = Self::READ;
    /// Read-write memory.
    pub const RW: Self = Self::from_bits_truncate(Self::READ.bits() | Self::WRITE.bits());
    /// Read-execute memory.
    pub const RX: Self = Self::from_bits_truncate(Self::READ.bits() | Self::EXECUTE.bits());
    // No write-execute for W^X protection.
}

/// Translates a `ProtFlags` to a `MappingFlags`.
impl Into<MappingFlags> for ProtFlags {
    fn into(self) -> MappingFlags {
        let mut flags = MappingFlags::USER;
        if self.contains(ProtFlags::READ) {
            flags |= MappingFlags::READABLE;
        }
        if self.contains(ProtFlags::WRITE) {
            flags |= MappingFlags::WRITABLE;
        }
        if self.contains(ProtFlags::EXECUTE) {
            flags |= MappingFlags::EXECUTABLE;
        }
        flags
    }
}

bitflags! {
    /// `MmapFlags` determines whether updates to the mapping are
    /// visible to other processes mapping the same region, and whether
    /// updates are carried through to the underlying file.
    #[derive(Debug)]
    pub struct MmapFlags: u32 {
        /// Modifications to this memory are shared
        const MAP_SHARED = 1 << 0;
        /// Modifications to this memory are private
        const MAP_PRIVATE = 1 << 1;
        /// Don't interpret addr as a hint: place the mapping at
        /// exactly that address.
        const MAP_FIXED = 1 << 4;
    }
}

impl Command<UserSpace> for Mmap {
    fn execute(&self, state: &mut UserSpace) -> ExecutionResult {
        // Check flags
        let shared = self.flags.contains(MmapFlags::MAP_SHARED);
        let private = self.flags.contains(MmapFlags::MAP_PRIVATE);
        if !shared && !private {
            return Err(linux_err!(EINVAL));
        }
        // Check fixed
        let fixed = self.flags.contains(MmapFlags::MAP_FIXED);
        if fixed {
            // If `fixed`, addr must always be aligned to page size
            if !check_align(self.addr, state.config.page_size) {
                return Err(linux_err!(EINVAL));
            }
            // addr must be in the user space
            if self.addr < state.config.ustart || self.addr + self.len >= state.config.uend {
                return Err(linux_err!(ENOMEM));
            }
        }
        // Align addr and len
        let addr = floor(self.addr, state.config.page_size);
        let len = ceil(self.len, state.config.page_size);
        // Handle fixed and non-fixed cases
        if fixed {
            // Split overlapped intervals
            let new = Interval::new(addr, addr + len, self.prot.into());
            let mut new_owned = Vec::new();
            // Split overlapped intervals and reinsert them
            for seg in state.segments.iter() {
                new_owned.extend(seg.subtract(&new));
            }
            new_owned.push(new);
            state.segments = ValueList(new_owned);
            Ok(addr)
        } else {
            // Find free intervals
            state.segments.sort_by(|a, b| a.left.cmp(&b.left));
            let mut cur_left = core::cmp::max(state.config.ustart, self.addr);
            for interval in state.segments.iter() {
                if cur_left + len <= interval.left {
                    break;
                }
                cur_left = interval.right;
            }
            // Check if not reach upper bound
            if cur_left + len > state.config.uend {
                return Err(linux_err!(ENOMEM));
            }
            let new = Interval::new(cur_left, cur_left + len, self.prot.into());
            state.segments.push(new);
            Ok(cur_left)
        }
    }

    fn stringify(&self) -> String {
        format!(
            "mmap({},{},{},{})",
            self.addr,
            self.len,
            self.prot.bits(),
            self.flags.bits(),
        )
    }
}

/// [`Munmap`] removes a mapping from the virtual address
/// space of the calling process.
///
/// Ref: https://man7.org/linux/man-pages/man2/munmap.2.html
#[derive(Debug)]
pub struct Munmap {
    /// The starting address of unmapping.
    pub addr: usize,
    /// The length of unmapping.
    pub len: usize,
}

impl Command<UserSpace> for Munmap {
    fn execute(&self, state: &mut UserSpace) -> ExecutionResult {
        // Check alignment
        if !check_align(self.addr, state.config.page_size) {
            return Err(linux_err!(EINVAL));
        }
        // Check size
        if self.addr < state.config.ustart || self.addr + self.len >= state.config.uend {
            return Err(linux_err!(EINVAL));
        }
        // Align to page size
        let addr = floor(self.addr, state.config.page_size);
        let len = ceil(self.len, state.config.page_size);
        let unmapped = Interval::new(addr, addr + len, ProtFlags::RO.into());
        // Remove the interval
        let mut new_owned = Vec::new();
        for interval in state.segments.iter() {
            new_owned.extend(interval.subtract(&unmapped));
        }
        state.segments = ValueList(new_owned);
        Ok(addr)
    }
    fn stringify(&self) -> String {
        format!("munmap({},{})", self.addr, self.len)
    }
}

/// [`Mprotect`] changes the access protections for the calling
/// process's memory pages containing any part of the address range
/// in the interval [addr, addr+len-1].
#[derive(Debug)]
pub struct Mprotect {
    /// The starting address of protection.
    pub start: usize,
    /// The length of protection.
    pub len: usize,
    /// The protection flags.
    pub flags: ProtFlags,
}

/// Check if `value` is aligned to `alignment`.
fn check_align(value: usize, alignment: usize) -> bool {
    value % alignment == 0
}

/// Floor `value` to the nearest multiple of `alignment`.
fn floor(value: usize, alignment: usize) -> usize {
    value / alignment * alignment
}

/// Ceil `value` to the nearest multiple of `alignment`.
fn ceil(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) / alignment * alignment
}
