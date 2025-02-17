//! FAT16 file allocation table entry

/// Represents a 16-bit FAT entry pointing to the next cluster in a chain
#[derive(Debug, Clone, Copy)]
pub struct FatEntry {
    /// Cluster number or special value (0=free, >=0xFFF8=end)
    pub cluster: u16,
}

impl FatEntry {
    /// Returns true if this entry marks the end of a cluster chain
    pub fn is_end_of_chain(&self) -> bool {
        self.cluster >= 0xFFF8
    }

    /// Returns true if this cluster is unused/free
    pub fn is_free(&self) -> bool {
        self.cluster == 0
    }
}
