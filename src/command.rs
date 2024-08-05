use crate::{linux_err, MappingFlags, UserSpace};
use km_checker::{
    impl_to_bytes, model_command,
    state::{Interval, ValueList},
    Command,
};
use km_command::mem::{MmapFlags, ProtFlags};

model_command!(km_command::mem, Brk);

impl Command<UserSpace> for Brk {
    fn execute(&self, state: &mut UserSpace) -> isize {
        if self.addr < state.config.heap_bottom
            || self.addr > state.config.heap_bottom + state.config.max_heap_size
        {
            return linux_err!(ENOMEM);
        }
        // If heap segment exists
        let mut has_heap_seg = false;
        for seg in state.segments.iter_mut() {
            if seg.right == ceil(state.config.heap_top, state.config.page_size) {
                seg.right = ceil(self.addr, state.config.page_size);
                has_heap_seg = true;
                break;
            }
        }
        // If heap segment does not exist, create one
        if !has_heap_seg {
            state.segments.push(Interval::new(
                state.config.heap_bottom,
                ceil(self.addr, state.config.page_size),
                prot_flags_to_mapping_flags(ProtFlags::READ | ProtFlags::WRITE),
            ));
            state.segments.sort_by(|a, b| a.left.cmp(&b.left));
        }
        state.config.heap_top = self.addr;
        0
    }
    impl_to_bytes!();
}

model_command!(km_command::mem, Sbrk);

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
    impl_to_bytes!();
}

model_command!(km_command::mem, Mmap);

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
            let mut new_segments = Vec::new();
            // Split overlapped intervals and reinsert them
            for seg in state.segments.iter() {
                new_segments.extend(seg.subtract(&new));
            }
            new_segments.push(new);
            state.segments = ValueList(new_segments);
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
    impl_to_bytes!();
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
    impl_to_bytes!();
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
