use crate::{linux_err, MappingFlags, UserSpace};
use bitflags::bitflags;
use kernel_model_lib::{Command, Interval, ValueList};

// Syscall id
pub const SYSCALL_BRK: u16 = 45;
pub const SYSCALL_SBRK: u16 = 91;
pub const SYSCALL_MMAP: u16 = 9;
pub const SYSCALL_MUNMAP: u16 = 11;

/// [`Brk`] and [`Sbrk] change the location of the program break,
/// which defines the end of the process's data segment.
///
/// Ref: https://man7.org/linux/man-pages/man2/brk.2.html
#[derive(Debug)]
pub struct Brk {
    /// The new program break.
    pub addr: usize,
}

impl Command<UserSpace> for Brk {
    fn execute(&self, state: &mut UserSpace) -> isize {
        if self.addr > state.config.heap_bottom
            && self.addr <= state.config.heap_bottom + state.config.max_heap_size
        {
            for seg in state.segments.iter_mut() {
                if seg.right == ceil(state.config.heap_top, state.config.page_size) {
                    seg.right = ceil(self.addr, state.config.page_size);
                    break;
                }
            }
            state.config.heap_top = self.addr;
            0
        } else {
            linux_err!(ENOMEM)
        }
    }
    fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&SYSCALL_BRK.to_ne_bytes());
        bytes.extend_from_slice(&self.addr.to_ne_bytes());
        bytes
    }
}

/// Like `brk`, but return the old program break on success.
///
/// Ref: https://man7.org/linux/man-pages/man2/brk.2.html
#[derive(Debug)]
pub struct Sbrk {
    /// The increment to the program break.
    pub increment: isize,
}

impl Command<UserSpace> for Sbrk {
    fn execute(&self, state: &mut UserSpace) -> isize {
        let old_brk = state.config.heap_top;
        if self.increment == 0 {
            return old_brk as isize;
        }
        let addr = (old_brk as isize + self.increment) as usize;
        let res = Brk { addr }.execute(state);
        if res < 0 {
            res
        } else {
            old_brk as isize
        }
    }
    fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&SYSCALL_SBRK.to_ne_bytes());
        bytes.extend_from_slice(&self.increment.to_ne_bytes());
        bytes
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
    fn execute(&self, state: &mut UserSpace) -> isize {
        // Check flags
        let shared = self.flags.contains(MmapFlags::MAP_SHARED);
        let private = self.flags.contains(MmapFlags::MAP_PRIVATE);
        if !shared && !private {
            return linux_err!(EINVAL);
        }
        // Check fixed
        let fixed = self.flags.contains(MmapFlags::MAP_FIXED);
        if fixed {
            // If `fixed`, addr must always be aligned to page size
            if !check_align(self.addr, state.config.page_size) {
                return linux_err!(EINVAL);
            }
            // addr must be in the user space
            if self.addr < state.config.ustart || self.addr + self.len >= state.config.uend {
                return linux_err!(ENOMEM);
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
            state.segments.sort_by(|a, b| a.left.cmp(&b.left));
            addr as isize
        } else {
            // Find free intervals
            let mut cur_left = core::cmp::max(state.config.ustart, self.addr);
            for interval in state.segments.iter() {
                if cur_left + len <= interval.left {
                    break;
                }
                cur_left = interval.right;
            }
            // Check if not reach upper bound
            if cur_left + len > state.config.uend {
                return linux_err!(ENOMEM);
            }
            let new = Interval::new(cur_left, cur_left + len, self.prot.into());
            state.segments.push(new);
            state.segments.sort_by(|a, b| a.left.cmp(&b.left));
            cur_left as isize
        }
    }
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&SYSCALL_MMAP.to_ne_bytes());
        buf.extend_from_slice(&self.addr.to_ne_bytes());
        buf.extend_from_slice(&self.len.to_ne_bytes());
        buf.extend_from_slice(&self.prot.bits().to_ne_bytes());
        buf.extend_from_slice(&self.flags.bits().to_ne_bytes());
        buf
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
    fn execute(&self, state: &mut UserSpace) -> isize {
        // Check alignment
        if !check_align(self.addr, state.config.page_size) {
            return linux_err!(EINVAL);
        }
        // Check size
        if self.addr < state.config.ustart || self.addr + self.len >= state.config.uend {
            return linux_err!(EINVAL);
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
        addr as isize
    }
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&SYSCALL_MUNMAP.to_ne_bytes());
        buf.extend_from_slice(&self.addr.to_ne_bytes());
        buf.extend_from_slice(&self.len.to_ne_bytes());
        buf
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
