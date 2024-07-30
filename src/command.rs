use crate::{linux_err, MappingFlags, UserSpace};
use kernel_model_lib::{impl_serialize, model_command, Command, Interval, Serialize, ValueList};
use km_command::mem::{MmapFlags, ProtFlags};

model_command!(km_command::mem, Brk);
impl_serialize!(Brk, postcard::to_allocvec);

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
}

model_command!(km_command::mem, Sbrk);
impl_serialize!(Sbrk, postcard::to_allocvec);

impl Command<UserSpace> for Sbrk {
    fn execute(&self, state: &mut UserSpace) -> isize {
        let old_brk = state.config.heap_top;
        if self.increment == 0 {
            return old_brk as isize;
        }
        let addr = (old_brk as isize + self.increment) as usize;
        let res = Brk(km_command::mem::Brk::new(addr)).execute(state);
        if res < 0 {
            res
        } else {
            old_brk as isize
        }
    }
}

model_command!(km_command::mem, Mmap);
impl_serialize!(Mmap, postcard::to_allocvec);

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
            let new = Interval::new(addr, addr + len, prot_flags_to_mapping_flags(self.prot));
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
            let new = Interval::new(
                cur_left,
                cur_left + len,
                prot_flags_to_mapping_flags(self.prot),
            );
            state.segments.push(new);
            state.segments.sort_by(|a, b| a.left.cmp(&b.left));
            cur_left as isize
        }
    }
}

fn prot_flags_to_mapping_flags(prot: ProtFlags) -> MappingFlags {
    let mut flags = MappingFlags::USER | MappingFlags::VALID;
    if prot.contains(ProtFlags::READ) {
        flags |= MappingFlags::READABLE;
    }
    if prot.contains(ProtFlags::WRITE) {
        flags |= MappingFlags::WRITABLE;
    }
    if prot.contains(ProtFlags::EXECUTE) {
        flags |= MappingFlags::EXECUTABLE;
    }
    flags
}

model_command!(km_command::mem, Munmap);
impl_serialize!(Munmap, postcard::to_allocvec);

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
        let unmapped = Interval::new(addr, addr + len, MappingFlags::empty());
        // Remove the interval
        let mut new_owned = Vec::new();
        for interval in state.segments.iter() {
            new_owned.extend(interval.subtract(&unmapped));
        }
        state.segments = ValueList(new_owned);
        addr as isize
    }
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
