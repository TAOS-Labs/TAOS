//! FAT16 file implementation with cluster-chain based I/O

use super::{constants::*, fat_entry::FatEntry, *};

/// Represents an open file on a FAT16 filesystem
pub struct Fat16File {
    /// Whether file is valid/open
    pub valid: bool,

    /// Current cluster being accessed
    pub current_cluster: u16,

    /// Current position in file
    pub position: u64,

    /// Total file size in bytes
    pub size: u64,

    /// Size of each cluster in bytes
    pub cluster_size: usize,

    /// Starting sector of FAT
    pub fat_start: u64,

    /// Starting sector of data area
    pub data_start: u64,

    /// Location of directory entry
    pub entry_position: u64,
}

#[async_trait]
impl File for Fat16File {
    async fn read_with_device(
        &mut self,
        device: &mut dyn BlockDevice,
        buf: &mut [u8],
    ) -> Result<usize, FsError> {
        if self.position >= self.size {
            return Ok(0);
        }

        let mut bytes_read = 0;
        let mut buf_offset = 0;
        let bytes_to_read = min(buf.len(), (self.size - self.position) as usize);

        while bytes_read < bytes_to_read {
            let cluster_offset = (self.position % self.cluster_size as u64) as usize;
            let bytes_left_in_cluster = self.cluster_size - cluster_offset;
            let chunk_size = min(bytes_left_in_cluster, bytes_to_read - bytes_read);

            let sector = self.cluster_to_sector(self.current_cluster);
            let mut cluster_data = vec![0u8; self.cluster_size];

            let sectors_per_cluster = self.cluster_size / SECTOR_SIZE;
            for i in 0..sectors_per_cluster {
                let mut sector_data = vec![0u8; SECTOR_SIZE];
                device
                    .read_block(sector + i as u64, &mut sector_data)
                    .await?;
                let start = i * SECTOR_SIZE;
                cluster_data[start..start + SECTOR_SIZE].copy_from_slice(&sector_data);
            }

            buf[buf_offset..buf_offset + chunk_size]
                .copy_from_slice(&cluster_data[cluster_offset..cluster_offset + chunk_size]);

            bytes_read += chunk_size;
            buf_offset += chunk_size;
            self.position += chunk_size as u64;

            if cluster_offset + chunk_size == self.cluster_size {
                let next_cluster = self.read_fat_entry(device, self.current_cluster).await?;
                if next_cluster.is_end_of_chain() {
                    break;
                }
                self.current_cluster = next_cluster.cluster;
            }
        }

        Ok(bytes_read)
    }

    async fn write_with_device(
        &mut self,
        device: &mut dyn BlockDevice,
        buf: &[u8],
    ) -> Result<usize, FsError> {
        let mut bytes_written = 0;
        let mut buf_offset = 0;

        while bytes_written < buf.len() {
            let cluster_offset = (self.position % self.cluster_size as u64) as usize;
            let bytes_left_in_cluster = self.cluster_size - cluster_offset;
            let chunk_size = min(bytes_left_in_cluster, buf.len() - bytes_written);

            let sector = self.cluster_to_sector(self.current_cluster);
            let mut cluster_data = vec![0u8; self.cluster_size];

            let sectors_per_cluster = self.cluster_size / SECTOR_SIZE;
            for i in 0..sectors_per_cluster {
                let mut sector_data = vec![0u8; SECTOR_SIZE];
                device
                    .read_block(sector + i as u64, &mut sector_data)
                    .await?;
                let start = i * SECTOR_SIZE;
                cluster_data[start..start + SECTOR_SIZE].copy_from_slice(&sector_data);
            }

            cluster_data[cluster_offset..cluster_offset + chunk_size]
                .copy_from_slice(&buf[buf_offset..buf_offset + chunk_size]);

            for i in 0..sectors_per_cluster {
                let start = i * SECTOR_SIZE;
                device
                    .write_block(sector + i as u64, &cluster_data[start..start + SECTOR_SIZE])
                    .await?;
            }

            bytes_written += chunk_size;
            buf_offset += chunk_size;
            self.position += chunk_size as u64;
            self.size = max(self.size, self.position);

            if cluster_offset + chunk_size == self.cluster_size {
                let fat_entry = self.read_fat_entry(device, self.current_cluster).await?;
                if fat_entry.is_end_of_chain() {
                    let new_cluster = self.allocate_cluster(device).await?;
                    self.write_fat_entry(
                        device,
                        self.current_cluster,
                        FatEntry {
                            cluster: new_cluster,
                        },
                    )
                    .await?;
                    self.current_cluster = new_cluster;
                } else {
                    self.current_cluster = fat_entry.cluster;
                }
            }
        }

        self.update_directory_entry(device, self.size).await?;
        Ok(bytes_written)
    }

    fn seek(&mut self, pos: SeekFrom) -> Result<u64, FsError> {
        let new_pos = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::End(offset) => {
                if offset < 0 {
                    self.size
                        .checked_sub(offset.unsigned_abs())
                        .ok_or(FsError::InvalidOffset)?
                } else {
                    self.size
                        .checked_add(offset as u64)
                        .ok_or(FsError::InvalidOffset)?
                }
            }
            SeekFrom::Current(offset) => {
                if offset < 0 {
                    self.position
                        .checked_sub(offset.unsigned_abs())
                        .ok_or(FsError::InvalidOffset)?
                } else {
                    self.position
                        .checked_add(offset as u64)
                        .ok_or(FsError::InvalidOffset)?
                }
            }
        };

        if new_pos > self.size {
            return Err(FsError::InvalidOffset);
        }

        self.position = new_pos;
        Ok(new_pos)
    }

    fn flush(&mut self) -> Result<(), FsError> {
        Ok(()) // No buffering implemented
    }

    fn size(&self) -> u64 {
        self.size
    }
}

impl Fat16File {
    /// Reads FAT entry for given cluster
    pub async fn read_fat_entry(
        &self,
        device: &mut dyn BlockDevice,
        cluster: u16,
    ) -> Result<FatEntry, FsError> {
        let offset = cluster as u64 * FAT_ENTRY_SIZE as u64;
        let sector = self.fat_start + (offset / SECTOR_SIZE as u64);
        let sector_offset = (offset % SECTOR_SIZE as u64) as usize;

        let mut sector_data = vec![0u8; SECTOR_SIZE];
        device.read_block(sector, &mut sector_data).await?;

        let entry =
            u16::from_le_bytes([sector_data[sector_offset], sector_data[sector_offset + 1]]);

        Ok(FatEntry { cluster: entry })
    }

    /// Writes FAT entry for given cluster
    pub async fn write_fat_entry(
        &self,
        device: &mut dyn BlockDevice,
        cluster: u16,
        entry: FatEntry,
    ) -> Result<(), FsError> {
        let offset = cluster as u64 * FAT_ENTRY_SIZE as u64;
        let sector = self.fat_start + (offset / SECTOR_SIZE as u64);
        let sector_offset = (offset % SECTOR_SIZE as u64) as usize;

        let mut sector_data = vec![0u8; SECTOR_SIZE];
        device.read_block(sector, &mut sector_data).await?;

        let bytes = entry.cluster.to_le_bytes();
        sector_data[sector_offset] = bytes[0];
        sector_data[sector_offset + 1] = bytes[1];

        device.write_block(sector, &sector_data).await?;

        Ok(())
    }

    /// Updates size in directory entry
    pub async fn update_directory_entry(
        &self,
        device: &mut dyn BlockDevice,
        new_size: u64,
    ) -> Result<(), FsError> {
        let sector = self.entry_position / SECTOR_SIZE as u64;
        let offset = self.entry_position % SECTOR_SIZE as u64;

        let mut sector_buffer = vec![0u8; SECTOR_SIZE];
        device.read_block(sector, &mut sector_buffer).await?;

        let entry =
            unsafe { &mut *(sector_buffer.as_mut_ptr().add(offset as usize) as *mut DirEntry83) };
        entry.file_size = new_size as u32;

        device.write_block(sector, &sector_buffer).await?;
        Ok(())
    }

    /// Finds and allocates a free cluster
    pub async fn allocate_cluster(&self, device: &mut dyn BlockDevice) -> Result<u16, FsError> {
        let total_clusters = (self.data_start as usize) / self.cluster_size;

        for cluster in 2..total_clusters as u16 {
            let entry = self.read_fat_entry(device, cluster).await?;
            if entry.is_free() {
                self.write_fat_entry(device, cluster, FatEntry { cluster: 0xFFFF })
                    .await?;
                return Ok(cluster);
            }
        }

        Err(FsError::NoSpace)
    }

    /// Converts cluster number to absolute sector number
    pub fn cluster_to_sector(&self, cluster: u16) -> u64 {
        self.data_start + ((cluster as u64 - 2) * (self.cluster_size / SECTOR_SIZE) as u64)
    }
}
