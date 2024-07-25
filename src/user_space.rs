use crate::MappingFlags;
use kernel_model_lib::{AbstractState, Ignored, Interval, ValueList};

/// A state representing the memory layout of a user process.
#[derive(Debug, AbstractState)]
pub struct UserSpace {
    pub segments: ValueList<Interval<MappingFlags>>,
    pub config: Ignored<UserSpaceConfig>,
}

impl Default for UserSpace {
    fn default() -> Self {
        Self {
            segments: ValueList(vec![]),
            config: Ignored(UserSpaceConfig::default()),
        }
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
    /// Start address of user space
    pub ustart: usize,
    /// Sperator of .text and .rodata
    pub text_rodata_sep: usize,
    /// Seper of .rodata and .data
    pub rodata_rwdata_sep: usize,
    /// Heap bottom
    pub heap_bottom: usize,
    /// Heap top
    pub heap_top: usize,
    /// End address of user space
    pub uend: usize,
    /// Page size of the system.
    pub page_size: usize,
    /// Max heap size
    pub max_heap_size: usize,
}
