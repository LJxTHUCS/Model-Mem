use super::{
    command::{Brk, Mmap, Munmap, Sbrk},
    UserSpace,
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
    /// Enable sbrk syscall.
    pub sbrk: bool,
    /// Enable mmap syscall.
    pub mmap: bool,
    /// Enable munmap syscall.
    pub munmap: bool,
    /// Addr range for brk.
    pub brk_addr_range: (usize, usize),
    /// Increment range for sbrk.
    pub sbrk_incr_range: (isize, isize),
    /// Addr range for mmap and munmap.
    pub mmap_addr_range: (usize, usize),
    /// Len range for mmap and munmap.
    pub mmap_len_range: (usize, usize),
}

impl MemRandCommander {
    /// Generate a random brk command.
    fn new_brk(&self, rng: &mut ThreadRng) -> Brk {
        km_command::mem::Brk::new(
            Uniform::new(self.brk_addr_range.0, self.brk_addr_range.1).sample(rng),
        )
        .into()
    }
    /// Generate a random sbrk command.
    fn new_sbrk(&self, rng: &mut ThreadRng) -> Sbrk {
        km_command::mem::Sbrk::new(
            Uniform::new(self.sbrk_incr_range.0, self.sbrk_incr_range.1).sample(rng),
        )
        .into()
    }
    /// Generate a random mmap command.
    fn new_mmap(&self, rng: &mut ThreadRng) -> Mmap {
        km_command::mem::Mmap::new(
            Uniform::new(self.mmap_addr_range.0, self.mmap_addr_range.1).sample(rng),
            Uniform::new(self.mmap_len_range.0, self.mmap_len_range.1).sample(rng),
            km_command::mem::ProtFlags::from_bits_truncate(rand::random::<u8>()),
            km_command::mem::MmapFlags::from_bits_truncate(rand::random::<u32>()),
        )
        .into()
    }
    /// Generate a random munmap command.
    fn new_munmap(&self, rng: &mut ThreadRng) -> Munmap {
        km_command::mem::Munmap::new(
            Uniform::new(self.mmap_addr_range.0, self.mmap_addr_range.1).sample(rng),
            Uniform::new(self.mmap_len_range.0, self.mmap_len_range.1).sample(rng),
        )
        .into()
    }
}

impl Commander<UserSpace> for MemRandCommander {
    fn command(&mut self) -> Result<Box<dyn Command<UserSpace>>, Error> {
        let mut choices = Vec::new();
        if self.brk {
            choices.push(0);
        }
        if self.sbrk {
            choices.push(1);
        }
        if self.mmap {
            choices.push(2);
        }
        if self.munmap {
            choices.push(3);
        }
        let mut rng = rand::thread_rng();
        Ok(match choices.choose(&mut rng).unwrap() {
            0 => Box::new(self.new_brk(&mut rng)),
            1 => Box::new(self.new_sbrk(&mut rng)),
            2 => Box::new(self.new_mmap(&mut rng)),
            3 => Box::new(self.new_munmap(&mut rng)),
            _ => unreachable!(),
        })
    }
}
