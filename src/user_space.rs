use crate::MappingFlags;
use core::fmt::Debug;
use km_checker::{
    state::{Ignored, Interval, ValueList},
    AbstractState,
};

/// A state representing the memory layout of a user process.
#[derive(AbstractState, Default)]
pub struct UserSpace {
    pub segments: ValueList<Interval<MappingFlags>>,
    pub config: Ignored<UserSpaceConfig>,
}

impl Debug for UserSpace {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for seg in self.segments.iter() {
            f.write_fmt(format_args!(
                "[{:#x}~{:#x}] {:?}\n",
                seg.left, seg.right, seg.value
            ))?;
        }
        Ok(())
    }
}

impl UserSpace {
    pub const fn new(config: UserSpaceConfig) -> Self {
        Self {
            segments: ValueList(Vec::new()),
            config: Ignored(config),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct UserSpaceConfig {
    /// Page size of the system.
    pub page_size: usize,
    /// Start address of user space
    pub ustart: usize,
    /// End address of user space
    pub uend: usize,
    /// Heap bottom
    pub heap_bottom: usize,
    /// Heap top
    pub heap_top: usize,
    /// Max heap size
    pub max_heap_size: usize,
}
