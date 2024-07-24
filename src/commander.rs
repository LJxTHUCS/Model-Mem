use super::{
    command::{Brk, Mmap, Munmap},
    MmapFlags, ProtFlags, UserSpace,
};
use kernel_model_lib::{Command, Commander, Error};
use rand::{
    distributions::{Distribution, Uniform},
    rngs::ThreadRng,
    seq::SliceRandom,
};

/// A random commander that randomly chooses mm syscalls.
pub struct MemRandCommander {
    /// Enable brk syscall.
    pub brk: bool,
    /// Enable mmap syscall.
    pub mmap: bool,
    /// Enable munmap syscall.
    pub munmap: bool,
    /// Addr range for brk syscall.
    pub brk_addr_range: (usize, usize),
    /// Addr range for mmap and munmap.
    pub mmap_addr_range: (usize, usize),
    /// Len range for mmap and munmap.
    pub mmap_len_range: (usize, usize),
}

impl MemRandCommander {
    /// Generate a random brk command.
    fn new_brk(&self, rng: &mut ThreadRng) -> Brk {
        Brk {
            addr: Uniform::new(self.brk_addr_range.0, self.brk_addr_range.1).sample(rng),
        }
    }
    /// Generate a random mmap command.
    fn new_mmap(&self, rng: &mut ThreadRng) -> Mmap {
        Mmap {
            addr: Uniform::new(self.mmap_addr_range.0, self.mmap_addr_range.1).sample(rng),
            len: Uniform::new(self.mmap_len_range.0, self.mmap_len_range.1).sample(rng),
            flags: MmapFlags::from_bits_truncate(rand::random::<u32>()),
            prot: ProtFlags::from_bits_truncate(rand::random::<u8>()),
        }
    }
    /// Generate a random munmap command.
    fn new_munmap(&self, rng: &mut ThreadRng) -> Munmap {
        Munmap {
            addr: Uniform::new(self.mmap_addr_range.0, self.mmap_addr_range.1).sample(rng),
            len: Uniform::new(self.mmap_len_range.0, self.mmap_len_range.1).sample(rng),
        }
    }
}

impl Commander<UserSpace> for MemRandCommander {
    fn command(&mut self) -> Result<Box<dyn Command<UserSpace>>, Error> {
        let mut choices = Vec::new();
        if self.brk {
            choices.push(0);
        }
        if self.mmap {
            choices.push(1);
        }
        if self.munmap {
            choices.push(2);
        }
        let mut rng = rand::thread_rng();
        Ok(match choices.choose(&mut rng).unwrap() {
            0 => Box::new(self.new_brk(&mut rng)),
            1 => Box::new(self.new_mmap(&mut rng)),
            2 => Box::new(self.new_munmap(&mut rng)),
            _ => unreachable!(),
        })
    }
}
