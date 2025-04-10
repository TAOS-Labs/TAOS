//! FAT16 filesystem implementation

use super::*;
use alloc::{collections::BinaryHeap, vec};
use core::cmp::{max, min};

mod boot_sector;
mod constants;
mod dir_entry;
mod fat_entry;
mod file;

pub use boot_sector::BootSector;
use constants::*;
pub use dir_entry::DirEntry83;
pub use fat_entry::FatEntry;
pub use file::Fat16File;

/// FAT16 filesystem driver
pub struct Fat16<'a> {
    /// Underlying block device
    pub device: Box<dyn BlockDevice + 'a>,
    /// Boot sector containing filesystem parameters
    boot_sector: BootSector,
    /// Starting sector of first FAT
    fat_start: u64,
    /// Starting sector of root directory
    root_dir_start: u64,
    /// Starting sector of data area
    data_start: u64,
    /// Size of each cluster in bytes
    cluster_size: usize,
    /// Next available file descriptor
    fd_counter: usize,
    /// Pool of reusable file descriptors
    reuse_fds: BinaryHeap<usize>,
    /// Table of open files
    fd_table: Vec<Fat16File>,
}

impl<'a> Fat16<'a> {
    pub async fn format(mut device: Box<dyn BlockDevice + 'a>) -> Result<Self, FsError> {
        let total_blocks = device.total_blocks();
        let block_size = device.block_size();

        let sectors_per_cluster = 4; // Typically 4 for small drives
        let reserved_sectors = 1; // Boot sector
        let fat_count = 2;
        let root_dir_entries = ROOT_DIR_ENTRIES as u16;
        let root_dir_sectors = (root_dir_entries as usize * 32).div_ceil(block_size);

        // Calculate sectors per FAT
        let total_clusters = (total_blocks as usize - reserved_sectors as usize - root_dir_sectors)
            / sectors_per_cluster as usize;
        let sectors_per_fat = (total_clusters * 2).div_ceil(block_size);

        // Create boot sector
        let boot_sector = BootSector {
            jump_boot: [0xEB, 0x3C, 0x90], // Standard boot jump
            oem_name: *b"UTTAOS.0",
            bytes_per_sector: block_size as u16,
            sectors_per_cluster: sectors_per_cluster as u8,
            reserved_sectors,
            fat_count,
            root_dir_entries,
            total_sectors_16: if total_blocks < 65536 {
                total_blocks as u16
            } else {
                0
            },
            media_type: 0xF8, // Fixed disk
            sectors_per_fat: sectors_per_fat as u16,
            sectors_per_track: 63, // Apparently the standard?
            head_count: 255,       // Why not?
            hidden_sectors: 0,
            total_sectors_32: if total_blocks >= 65536 {
                total_blocks as u32
            } else {
                0
            },
            drive_number: 0x80, // Hard disk
            reserved1: 0,
            boot_signature: 0x29,
            volume_id: 0x12345678, // Random volume ID
            volume_label: *b"NO NAME    ",
            fs_type: *b"FAT16   ",
        };

        let boot_sector_bytes = unsafe {
            core::slice::from_raw_parts(
                &boot_sector as *const BootSector as *const u8,
                core::mem::size_of::<BootSector>(),
            )
        };
        let mut block_buf = vec![0u8; block_size];
        block_buf[..boot_sector_bytes.len()].copy_from_slice(boot_sector_bytes);
        block_buf[510] = 0x55; // Boot signature
        block_buf[511] = 0xAA;
        device.write_block(0, &block_buf).await?;

        let mut fat_block = vec![0u8; block_size];
        // First two FAT entries are reserved
        fat_block[0] = boot_sector.media_type;
        fat_block[1] = 0xFF;
        fat_block[2] = 0xFF;
        fat_block[3] = 0xFF;

        // Write first sector of each FAT
        for i in 0..fat_count {
            let fat_start = reserved_sectors as u64 + (i as u64 * sectors_per_fat as u64);
            device.write_block(fat_start, &fat_block).await?;
        }

        // Clear the rest of the FAT tables
        let zero_block = vec![0u8; block_size];
        for i in 0..fat_count {
            let fat_start = reserved_sectors as u64 + (i as u64 * sectors_per_fat as u64);
            for j in 1..sectors_per_fat {
                device
                    .write_block(fat_start + j as u64, &zero_block)
                    .await?;
            }
        }

        // Initialize empty root directory
        let root_dir_start = reserved_sectors as u64 + (fat_count as u64 * sectors_per_fat as u64);
        for i in 0..root_dir_sectors {
            device
                .write_block(root_dir_start + i as u64, &zero_block)
                .await?;
        }
        Fat16::new(device).await
    }

    pub async fn new(device: Box<dyn BlockDevice + 'a>) -> Result<Self, FsError> {
        let mut boot_sector_data = vec![0u8; SECTOR_SIZE];
        device.read_block(0, &mut boot_sector_data).await?;

        let boot_sector =
            unsafe { core::ptr::read(boot_sector_data.as_ptr() as *const BootSector) };

        let fat_start = boot_sector.reserved_sectors as u64;
        let sectors_per_fat = boot_sector.sectors_per_fat as u64;
        let root_dir_start = fat_start + (sectors_per_fat * boot_sector.fat_count as u64);
        let root_dir_sectors = (ROOT_DIR_ENTRIES * 32).div_ceil(SECTOR_SIZE);
        let data_start = root_dir_start + root_dir_sectors as u64;
        let cluster_size = boot_sector.sectors_per_cluster as usize * SECTOR_SIZE;
        let fd_counter = 0;
        let reuse_fds = BinaryHeap::new();
        let fd_table = Vec::new();

        Ok(Fat16 {
            device,
            boot_sector,
            fat_start,
            root_dir_start,
            data_start,
            cluster_size,
            fd_counter,
            reuse_fds,
            fd_table,
        })
    }

    async fn read_fat_entry(&self, cluster: u16) -> Result<FatEntry, FsError> {
        let offset = cluster as u64 * FAT_ENTRY_SIZE as u64;
        let sector = self.fat_start + (offset / SECTOR_SIZE as u64);
        let sector_offset = (offset % SECTOR_SIZE as u64) as usize;

        let mut sector_data = vec![0u8; SECTOR_SIZE];
        self.device.read_block(sector, &mut sector_data).await?;

        let entry =
            u16::from_le_bytes([sector_data[sector_offset], sector_data[sector_offset + 1]]);

        Ok(FatEntry { cluster: entry })
    }

    async fn write_fat_entry(&mut self, cluster: u16, entry: FatEntry) -> Result<(), FsError> {
        let offset = cluster as u64 * FAT_ENTRY_SIZE as u64;
        let sector = self.fat_start + (offset / SECTOR_SIZE as u64);
        let sector_offset = (offset % SECTOR_SIZE as u64) as usize;

        let mut sector_data = vec![0u8; SECTOR_SIZE];
        self.device.read_block(sector, &mut sector_data).await?;

        let bytes = entry.cluster.to_le_bytes();
        sector_data[sector_offset] = bytes[0];
        sector_data[sector_offset + 1] = bytes[1];

        self.device.write_block(sector, &sector_data).await?;

        // Write to second FAT table if it exists
        if self.boot_sector.fat_count > 1 {
            let second_fat_sector = sector + self.boot_sector.sectors_per_fat as u64;
            self.device
                .write_block(second_fat_sector, &sector_data)
                .await?;
        }

        Ok(())
    }

    async fn write_dir_entry(
        &mut self,
        dir_cluster: u16,
        entry: &DirEntry83,
    ) -> Result<(), FsError> {
        let entries_per_sector = SECTOR_SIZE / core::mem::size_of::<DirEntry83>();
        let mut sector_buffer = vec![0u8; SECTOR_SIZE];

        let (start_sector, num_sectors) = if dir_cluster == 0 {
            (
                self.root_dir_start,
                (ROOT_DIR_ENTRIES / entries_per_sector) as u64,
            )
        } else {
            let start_sector = self.cluster_to_sector(dir_cluster);
            let sectors_per_cluster = self.boot_sector.sectors_per_cluster as u64;
            (start_sector, sectors_per_cluster)
        };

        for sector_offset in 0..num_sectors {
            self.device
                .read_block(start_sector + sector_offset, &mut sector_buffer)
                .await?;

            for i in 0..entries_per_sector {
                let entry_ptr = unsafe {
                    &mut *(sector_buffer
                        .as_mut_ptr()
                        .add(i * core::mem::size_of::<DirEntry83>())
                        as *mut DirEntry83)
                };

                if entry_ptr.is_free() || entry_ptr.is_deleted() {
                    *entry_ptr = *entry;
                    self.device
                        .write_block(start_sector + sector_offset, &sector_buffer)
                        .await?;
                    return Ok(());
                }
            }
        }

        // Directory is full
        // Probably should be an error, but then again
        // Fancier filesystems just magically grow
        Err(FsError::NotSupported)
    }

    async fn init_directory(&mut self, cluster: u16, parent_cluster: u16) -> Result<(), FsError> {
        let dot_entry = DirEntry83::new_directory(".", cluster);
        let dotdot_entry = DirEntry83::new_directory("..", parent_cluster);

        let sector = self.cluster_to_sector(cluster);
        let mut sector_data = vec![0u8; SECTOR_SIZE];

        unsafe {
            *(sector_data.as_mut_ptr() as *mut DirEntry83) = dot_entry;
            *(sector_data
                .as_mut_ptr()
                .add(core::mem::size_of::<DirEntry83>()) as *mut DirEntry83) = dotdot_entry;
        }

        self.device.write_block(sector, &sector_data).await?;
        sector_data.fill(0);

        for i in 1..self.boot_sector.sectors_per_cluster {
            self.device
                .write_block(sector + i as u64, &sector_data)
                .await?;
        }

        Ok(())
    }

    async fn allocate_cluster(&mut self) -> Result<u16, FsError> {
        let total_clusters = (self.boot_sector.total_sectors_16 as usize
            - self.data_start as usize)
            / self.boot_sector.sectors_per_cluster as usize;

        for cluster in 2..total_clusters as u16 {
            let entry = self.read_fat_entry(cluster).await?;
            if entry.is_free() {
                self.write_fat_entry(cluster, FatEntry { cluster: 0xFFFF })
                    .await?;
                return Ok(cluster);
            }
        }

        // No free clusters
        Err(FsError::NotSupported)
    }

    fn cluster_to_sector(&self, cluster: u16) -> u64 {
        self.data_start + ((cluster as u64 - 2) * self.boot_sector.sectors_per_cluster as u64)
    }

    async fn find_entry(&self, path: &str) -> Result<(DirEntry83, u64), FsError> {
        let mut current_dir_cluster = 0;
        let components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

        if components.is_empty() {
            return Err(FsError::InvalidName);
        }

        let mut i = 0;
        while i < components.len() - 1 {
            let entry = self
                .find_entry_in_dir(current_dir_cluster, components[i])
                .await?;
            if !entry.0.is_directory() {
                return Err(FsError::NotFound);
            }
            current_dir_cluster = entry.0.start_cluster as u64;
            i += 1;
        }

        self.find_entry_in_dir(current_dir_cluster, components[components.len() - 1])
            .await
    }

    async fn remove_entry(&mut self, path: &str, is_dir: bool) -> Result<(), FsError> {
        let (entry, entry_pos) = self.find_entry(path).await?;

        if entry.is_directory() != is_dir {
            return Err(FsError::NotSupported);
        }

        let mut sector_buffer = vec![0u8; SECTOR_SIZE];
        let sector = entry_pos / SECTOR_SIZE as u64;
        let offset = entry_pos % SECTOR_SIZE as u64;

        self.device.read_block(sector, &mut sector_buffer).await?;
        sector_buffer[offset as usize] = DELETED_ENTRY_MARKER;
        self.device.write_block(sector, &sector_buffer).await?;

        let mut cluster = entry.start_cluster;
        while !self.read_fat_entry(cluster).await?.is_end_of_chain() {
            let next_cluster = self.read_fat_entry(cluster).await?.cluster;
            self.write_fat_entry(cluster, FatEntry { cluster: 0 })
                .await?;
            cluster = next_cluster;
        }
        self.write_fat_entry(cluster, FatEntry { cluster: 0 })
            .await?;

        Ok(())
    }

    async fn is_directory_empty(&mut self, dir_cluster: u16) -> Result<bool, FsError> {
        let entries_per_sector = SECTOR_SIZE / core::mem::size_of::<DirEntry83>();
        let mut sector_buffer = vec![0u8; SECTOR_SIZE];

        let sector = self.cluster_to_sector(dir_cluster);
        self.device.read_block(sector, &mut sector_buffer).await?;

        for i in 0..entries_per_sector {
            let entry = unsafe {
                &*(sector_buffer
                    .as_ptr()
                    .add(i * core::mem::size_of::<DirEntry83>())
                    as *const DirEntry83)
            };

            if entry.is_free() {
                break;
            }

            if !entry.is_deleted() {
                let name = entry.get_name();
                if name != "." && name != ".." {
                    return Ok(false); // Found a regular entry
                }
            }
        }

        Ok(true)
    }

    async fn find_entry_in_dir(
        &self,
        dir_cluster: u64,
        name: &str,
    ) -> Result<(DirEntry83, u64), FsError> {
        let entries_per_sector = SECTOR_SIZE / core::mem::size_of::<DirEntry83>();
        let mut sector_buffer = vec![0u8; SECTOR_SIZE];

        let (start_sector, num_sectors) = if dir_cluster == 0 {
            (
                self.root_dir_start,
                (ROOT_DIR_ENTRIES / entries_per_sector) as u64,
            )
        } else {
            let start_sector = self.cluster_to_sector(dir_cluster as u16);
            let sectors_per_cluster = self.boot_sector.sectors_per_cluster as u64;
            (start_sector, sectors_per_cluster)
        };

        for sector_offset in 0..num_sectors {
            self.device
                .read_block(start_sector + sector_offset, &mut sector_buffer)
                .await?;

            for i in 0..entries_per_sector {
                let entry = unsafe {
                    &*(sector_buffer
                        .as_ptr()
                        .add(i * core::mem::size_of::<DirEntry83>())
                        as *const DirEntry83)
                };

                if entry.is_free() {
                    break;
                }

                if !entry.is_deleted() && entry.get_name() == name {
                    let entry_offset = i * core::mem::size_of::<DirEntry83>();
                    let sector_offset_bytes = (start_sector + sector_offset) * SECTOR_SIZE as u64;
                    let absolute_position = sector_offset_bytes + entry_offset as u64;
                    return Ok((*entry, absolute_position));
                }
            }
        }

        Err(FsError::NotFound)
    }
}

#[async_trait]
impl FileSystem for Fat16<'_> {
    async fn create_file(&mut self, path: &str) -> Result<(), FsError> {
        let (parent_path, name) = match path.rfind('/') {
            Some(pos) => (&path[..pos], &path[pos + 1..]),
            None => ("", path),
        };

        if name.len() > MAX_FILENAME_LENGTH + MAX_EXTENSION_LENGTH + 1 {
            return Err(FsError::InvalidName);
        }

        let (base_name, extension) = match name.rfind('.') {
            Some(pos) => (&name[..pos], &name[pos + 1..]),
            None => (name, ""),
        };

        if self.find_entry(path).await.is_ok() {
            return Err(FsError::AlreadyExists);
        }

        let cluster = self.allocate_cluster().await?;

        let entry = DirEntry83::new_file(base_name, extension, cluster);

        let parent_cluster = if parent_path.is_empty() || parent_path == "/" {
            0
        } else {
            self.find_entry(parent_path).await?.0.start_cluster
        };

        self.write_dir_entry(parent_cluster, &entry).await?;

        Ok(())
    }

    async fn create_dir(&mut self, path: &str) -> Result<(), FsError> {
        let (parent_path, name) = match path.rfind('/') {
            Some(pos) => (&path[..pos], &path[pos + 1..]),
            None => ("", path),
        };

        if name.len() > MAX_FILENAME_LENGTH {
            return Err(FsError::InvalidName);
        }

        if self.find_entry(path).await.is_ok() {
            return Err(FsError::AlreadyExists);
        }

        let cluster = self.allocate_cluster().await?;

        let entry = DirEntry83::new_directory(name, cluster);

        let parent_cluster = if parent_path.is_empty() || parent_path == "/" {
            0
        } else {
            self.find_entry(parent_path).await?.0.start_cluster
        };

        self.init_directory(cluster, parent_cluster).await?;

        self.write_dir_entry(parent_cluster, &entry).await?;

        Ok(())
    }

    async fn remove_file(&mut self, path: &str) -> Result<(), FsError> {
        self.remove_entry(path, false).await
    }

    async fn remove_dir(&mut self, path: &str) -> Result<(), FsError> {
        let (entry, _) = self.find_entry(path).await?;

        if !entry.is_directory() {
            return Err(FsError::NotSupported);
        }

        if !self.is_directory_empty(entry.start_cluster).await? {
            return Err(FsError::DirectoryNotEmpty);
        }

        self.remove_entry(path, true).await
    }

    async fn open_file(&mut self, path: &str) -> Result<usize, FsError> {
        let (entry, entry_pos) = self.find_entry(path).await?;

        if entry.is_directory() {
            return Err(FsError::NotSupported);
        }

        let file = Fat16File {
            valid: true,
            current_cluster: entry.start_cluster,
            position: 0,
            size: entry.file_size as u64,
            cluster_size: self.cluster_size,
            fat_start: self.fat_start,
            data_start: self.data_start,
            entry_position: entry_pos,
        };

        let fd = if let Some(reused_fd) = self.reuse_fds.pop() {
            assert!(!self.fd_table[reused_fd].valid);
            self.fd_table[reused_fd] = file;
            reused_fd
        } else {
            let new_fd = self.fd_counter;
            self.fd_table.push(file);
            self.fd_counter += 1;
            new_fd
        };

        assert!(fd != usize::MAX, "File Descriptor is not a valid value.");
        Ok(fd)
    }

    fn close_file(&mut self, fd: usize) {
        let file: &mut Fat16File = self.fd_table.get_mut(fd).expect("Invalid file descriptor.");
        assert!(file.valid, "Cannot close an invailid file descriptor.");

        file.valid = false;
        file.current_cluster = 0;
        file.position = 0;
        file.size = 0_u64;
        file.cluster_size = 0;
        file.fat_start = 0;
        file.data_start = 0;
        file.entry_position = 0;

        self.reuse_fds.push(fd);
    }

    async fn write_file(&mut self, fd: usize, buf: &[u8]) -> Result<usize, FsError> {
        let mut bytes_written = 0;
        let mut buf_offset = 0;

        let file: &mut Fat16File = self.fd_table.get_mut(fd).expect("Invalid file descriptor.");

        while bytes_written < buf.len() {
            let cluster_offset = (file.position % file.cluster_size as u64) as usize;
            let bytes_left_in_cluster = file.cluster_size - cluster_offset;
            let chunk_size = min(bytes_left_in_cluster, buf.len() - bytes_written);

            let sector = file.cluster_to_sector(file.current_cluster);
            let mut cluster_data = vec![0u8; file.cluster_size];

            let sectors_per_cluster = file.cluster_size / SECTOR_SIZE;
            for i in 0..sectors_per_cluster {
                let mut sector_data = vec![0u8; SECTOR_SIZE];
                self.device
                    .read_block(sector + i as u64, &mut sector_data)
                    .await?;
                let start = i * SECTOR_SIZE;
                cluster_data[start..start + SECTOR_SIZE].copy_from_slice(&sector_data);
            }

            cluster_data[cluster_offset..cluster_offset + chunk_size]
                .copy_from_slice(&buf[buf_offset..buf_offset + chunk_size]);

            for i in 0..sectors_per_cluster {
                let start = i * SECTOR_SIZE;
                self.device
                    .write_block(sector + i as u64, &cluster_data[start..start + SECTOR_SIZE])
                    .await?;
            }

            bytes_written += chunk_size;
            buf_offset += chunk_size;
            file.position += chunk_size as u64;
            file.size = max(file.size, file.position);

            if cluster_offset + chunk_size == file.cluster_size {
                let fat_entry = file
                    .read_fat_entry(&mut *self.device, file.current_cluster)
                    .await?;
                if fat_entry.is_end_of_chain() {
                    let new_cluster = file.allocate_cluster(&mut *self.device).await?;
                    file.write_fat_entry(
                        &mut *self.device,
                        file.current_cluster,
                        FatEntry {
                            cluster: new_cluster,
                        },
                    )
                    .await?;
                    file.current_cluster = new_cluster;
                } else {
                    file.current_cluster = fat_entry.cluster;
                }
            }
        }

        file.update_directory_entry(&mut *self.device, file.size)
            .await?;
        Ok(bytes_written)
    }

    fn seek_file(&mut self, fd: usize, pos: SeekFrom) -> Result<u64, FsError> {
        let file: &mut Fat16File = self.fd_table.get_mut(fd).expect("Invalid file descriptor.");

        let new_pos = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::End(offset) => {
                if offset < 0 {
                    file.size
                        .checked_sub(offset.unsigned_abs())
                        .ok_or(FsError::InvalidOffset)?
                } else {
                    file.size
                        .checked_add(offset as u64)
                        .ok_or(FsError::InvalidOffset)?
                }
            }
            SeekFrom::Current(offset) => {
                if offset < 0 {
                    file.position
                        .checked_sub(offset.unsigned_abs())
                        .ok_or(FsError::InvalidOffset)?
                } else {
                    file.position
                        .checked_add(offset as u64)
                        .ok_or(FsError::InvalidOffset)?
                }
            }
        };

        if new_pos > file.size {
            return Err(FsError::InvalidOffset);
        }

        file.position = new_pos;
        Ok(new_pos)
    }

    async fn read_file(&mut self, fd: usize, buf: &mut [u8]) -> Result<usize, FsError> {
        let file: &mut Fat16File = self.fd_table.get_mut(fd).expect("Invalid file descriptor.");

        if file.position >= file.size {
            return Ok(0);
        }

        let mut bytes_read = 0;
        let mut buf_offset = 0;
        let bytes_to_read = min(buf.len(), (file.size - file.position) as usize);

        while bytes_read < bytes_to_read {
            let cluster_offset = (file.position % file.cluster_size as u64) as usize;
            let bytes_left_in_cluster = file.cluster_size - cluster_offset;
            let chunk_size = min(bytes_left_in_cluster, bytes_to_read - bytes_read);

            let sector = file.cluster_to_sector(file.current_cluster);
            let mut cluster_data = vec![0u8; file.cluster_size];

            let sectors_per_cluster = file.cluster_size / SECTOR_SIZE;
            for i in 0..sectors_per_cluster {
                let mut sector_data = vec![0u8; SECTOR_SIZE];
                self.device
                    .read_block(sector + i as u64, &mut sector_data)
                    .await?;
                let start = i * SECTOR_SIZE;
                cluster_data[start..start + SECTOR_SIZE].copy_from_slice(&sector_data);
            }

            buf[buf_offset..buf_offset + chunk_size]
                .copy_from_slice(&cluster_data[cluster_offset..cluster_offset + chunk_size]);

            bytes_read += chunk_size;
            buf_offset += chunk_size;
            file.position += chunk_size as u64;

            if cluster_offset + chunk_size == file.cluster_size {
                let next_cluster = file
                    .read_fat_entry(&mut *self.device, file.current_cluster)
                    .await?;
                if next_cluster.is_end_of_chain() {
                    break;
                }
                file.current_cluster = next_cluster.cluster;
            }
        }

        Ok(bytes_read)
    }

    async fn read_dir(&self, path: &str) -> Result<Vec<DirEntry>, FsError> {
        let (entry, _) = if path.is_empty() || path == "/" {
            // Root directory - return entry with dummy position
            (
                DirEntry83 {
                    name: *b"        ",
                    ext: *b"   ",
                    attributes: ATTR_DIRECTORY,
                    reserved: [0; 10],
                    time: 0,
                    date: 0,
                    start_cluster: 0,
                    file_size: 0,
                },
                0,
            )
        } else {
            self.find_entry(path).await?
        };

        if !entry.is_directory() {
            return Err(FsError::NotSupported);
        }

        let mut result = Vec::new();
        let entries_per_sector = SECTOR_SIZE / core::mem::size_of::<DirEntry83>();
        let mut sector_buffer = vec![0u8; SECTOR_SIZE];

        let (start_sector, num_sectors) = if entry.start_cluster == 0 {
            (
                self.root_dir_start,
                (ROOT_DIR_ENTRIES / entries_per_sector) as u64,
            )
        } else {
            let start_sector = self.cluster_to_sector(entry.start_cluster);
            let sectors_per_cluster = self.boot_sector.sectors_per_cluster as u64;
            (start_sector, sectors_per_cluster)
        };

        for sector_offset in 0..num_sectors {
            self.device
                .read_block(start_sector + sector_offset, &mut sector_buffer)
                .await?;

            for i in 0..entries_per_sector {
                let fat_entry = unsafe {
                    &*(sector_buffer
                        .as_ptr()
                        .add(i * core::mem::size_of::<DirEntry83>())
                        as *const DirEntry83)
                };

                if fat_entry.is_free() {
                    break;
                }

                if !fat_entry.is_deleted() && fat_entry.name[0] != 0x2E {
                    result.push(DirEntry {
                        name: fat_entry.get_name(),
                        metadata: FileMetadata {
                            size: fat_entry.file_size as u64,
                            is_dir: fat_entry.is_directory(),
                            created: 0, // FAT16 doesn't store creation time
                            modified: ((entry.date as u64) << 16) | (entry.time as u64),
                            permissions: FilePermissions {
                                readable: true,
                                writable: fat_entry.attributes & ATTR_READ_ONLY == 0,
                                executable: false,
                            },
                        },
                    });
                }
            }
        }

        Ok(result)
    }

    async fn metadata(&self, path: &str) -> Result<FileMetadata, FsError> {
        let (entry, _) = self.find_entry(path).await?;

        Ok(FileMetadata {
            size: entry.file_size as u64,
            is_dir: entry.is_directory(),
            created: 0, // FAT16 doesn't store creation time
            modified: ((entry.date as u64) << 16) | (entry.time as u64),
            permissions: FilePermissions {
                readable: true,
                writable: entry.attributes & ATTR_READ_ONLY == 0,
                executable: false,
            },
        })
    }

    async fn rename(&mut self, from: &str, to: &str) -> Result<(), FsError> {
        let (src_entry, src_pos) = self.find_entry(from).await?;

        if self.find_entry(to).await.is_ok() {
            return Err(FsError::AlreadyExists);
        }

        let (parent_path, new_name) = match to.rfind('/') {
            Some(pos) => (&to[..pos], &to[pos + 1..]),
            None => ("", to),
        };

        let (base_name, extension) = match new_name.rfind('.') {
            Some(pos) => (&new_name[..pos], &new_name[pos + 1..]),
            None => (new_name, ""),
        };

        let mut new_entry = src_entry;
        let mut name_bytes = [0x20u8; 8]; // Space padded
        let mut ext_bytes = [0x20u8; 3]; // Space padded

        name_bytes[..base_name.len().min(8)]
            .copy_from_slice(&base_name.as_bytes()[..base_name.len().min(8)]);
        if !extension.is_empty() {
            ext_bytes[..extension.len().min(3)]
                .copy_from_slice(&extension.as_bytes()[..extension.len().min(3)]);
        }

        new_entry.name = name_bytes;
        new_entry.ext = ext_bytes;

        let mut sector_buffer = vec![0u8; SECTOR_SIZE];
        let entries_per_sector = SECTOR_SIZE / core::mem::size_of::<DirEntry83>();

        let dest_dir_cluster = if parent_path.is_empty() || parent_path == "/" {
            0
        } else {
            self.find_entry(parent_path).await?.0.start_cluster
        };

        let (start_sector, num_sectors) = if dest_dir_cluster == 0 {
            (
                self.root_dir_start,
                (ROOT_DIR_ENTRIES / entries_per_sector) as u64,
            )
        } else {
            let start_sector = self.cluster_to_sector(dest_dir_cluster);
            let sectors_per_cluster = self.boot_sector.sectors_per_cluster as u64;
            (start_sector, sectors_per_cluster)
        };

        let mut found_pos = None;
        'outer: for sector_offset in 0..num_sectors {
            self.device
                .read_block(start_sector + sector_offset, &mut sector_buffer)
                .await?;

            for i in 0..entries_per_sector {
                let entry_offset = i * core::mem::size_of::<DirEntry83>();
                let entry =
                    unsafe { &*(sector_buffer.as_ptr().add(entry_offset) as *const DirEntry83) };

                if entry.is_free() || entry.is_deleted() {
                    found_pos = Some((start_sector + sector_offset, entry_offset));
                    break 'outer;
                }
            }
        }

        let (dest_sector, dest_offset) = found_pos.ok_or(FsError::NotSupported)?;

        self.device
            .read_block(dest_sector, &mut sector_buffer)
            .await?;
        unsafe {
            *(sector_buffer.as_mut_ptr().add(dest_offset) as *mut DirEntry83) = new_entry;
        }
        self.device.write_block(dest_sector, &sector_buffer).await?;

        self.device
            .read_block(src_pos / SECTOR_SIZE as u64, &mut sector_buffer)
            .await?;
        sector_buffer[(src_pos % SECTOR_SIZE as u64) as usize] = DELETED_ENTRY_MARKER;
        self.device
            .write_block(src_pos / SECTOR_SIZE as u64, &sector_buffer)
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use crate::filesys::{block::memory::MemoryBlockDevice, fat16::Fat16, FileSystem, SeekFrom};
    use alloc::boxed::Box;

    #[test_case]
    async fn fat_test() {
        // let lock = SD_CARD.lock().clone().unwrap();
        let block_device = MemoryBlockDevice::new(400, 512);
        let device = Box::new(block_device);

        // Format the filesystem
        let mut fs = Fat16::format(device)
            .await
            .expect("Failed to format filesystem");

        // Test directory operations
        fs.create_dir("/test_dir")
            .await
            .expect("Failed to create directory");
        fs.create_dir("/test_dir/subdir")
            .await
            .expect("Failed to create subdirectory");

        // Create a test file
        fs.create_file("/test_dir/test.txt")
            .await
            .expect("FailedBlockDevice to create file");
        let fd = fs
            .open_file("/test_dir/test.txt")
            .await
            .expect("Failed to open file");

        // Write test data
        let test_data = b"Hello, TaOS FAT16!";
        let written = fs.write_file(fd, test_data).await.expect("Failed to write");
        assert_eq!(written, test_data.len(), "Write length mismatch");

        fs.seek_file(fd, SeekFrom::Start(0))
            .expect("Failed to seek to start");
        let mut read_buf = [0u8; 32];
        let read = fs
            .read_file(fd, &mut read_buf)
            .await
            .expect("Failed to read");
        assert_eq!(read, test_data.len(), "Read length mismatch");
        assert_eq!(&read_buf[..read], test_data, "Read data mismatch");

        // List directory contents
        let entries = fs
            .read_dir("/test_dir")
            .await
            .expect("Failed to read directory");
        assert!(!entries.is_empty(), "Directory should not be empty");
        assert_eq!(entries.len(), 2, "Directory should have exactly 2 entries"); // subdir and test.txt

        // Check file metadata
        let metadata = fs
            .metadata("/test_dir/test.txt")
            .await
            .expect("Failed to get metadata");
        assert_eq!(metadata.size, test_data.len() as u64, "File size mismatch");
        assert!(!metadata.is_dir, "Should not be a directory");

        // Test partial reads
        fs.seek_file(fd, SeekFrom::Start(7))
            .expect("Failed to seek");
        let mut partial_buf = [0u8; 4];
        let read = fs
            .read_file(fd, &mut partial_buf)
            .await
            .expect("Failed to read");
        assert_eq!(read, 4, "Partial read length mismatch");
        assert_eq!(&partial_buf[..read], b"TaOS", "Partial read data mismatch");

        // Close file and test removal
        fs.close_file(fd);

        fs.remove_file("/test_dir/test.txt")
            .await
            .expect("Failed to remove file");
        fs.remove_dir("/test_dir/subdir")
            .await
            .expect("Failed to remove subdirectory");
        fs.remove_dir("/test_dir")
            .await
            .expect("Failed to remove directory");

        // Verify root is empty
        let root_entries = fs
            .read_dir("/")
            .await
            .expect("Failed to read root directory");
        assert_eq!(root_entries.len(), 0, "Root directory should be empty");
    }
}
