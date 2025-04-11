pub mod allocator;
pub mod block_io;
pub mod cache;
pub mod filesystem;
pub mod ide;
pub mod node;
pub mod structures;

/// Get current Unix timestamp
pub fn get_current_time() -> u32 {
    // For now, return a dummy
    1234567890
}

#[cfg(test)]
mod tests {
    use alloc::{
        format,
        string::{String, ToString},
        sync::Arc,
        vec,
    };

    use crate::devices::sd_card::SD_CARD;

    use super::{
        filesystem::{Ext2, FilesystemError},
        structures::FileMode,
    };

    const MEDIUM_FILE: &[u8] = include_bytes!("../../../../resources/fonts/Comfortaa-Regular.ttf");

    // Helper function to create a test filesystem using the SD card
    async fn create_test_fs() -> Ext2 {
        let sd_card_lock = SD_CARD.lock();
        let sd_card = sd_card_lock.clone().unwrap();
        let sd_arc = Arc::new(sd_card);
        let fs = Ext2::new(sd_arc).await.unwrap();
        fs.mount().await.unwrap();
        fs
    }

    #[test_case]
    async fn test_read_font_file() {
        let fs = create_test_fs().await;
        let file = fs.read_file("/fonts/Comfortaa-Regular.ttf").await.unwrap();
        assert!(file == MEDIUM_FILE);
    }

    #[test_case]
    async fn test_mount_unmount() {
        let fs = create_test_fs().await;

        let block_size = fs.stats().unwrap().block_size;

        fs.unmount().await.unwrap();

        match fs.read_file("/test.txt").await {
            Err(FilesystemError::NotMounted) => {}
            _ => panic!("Expected NotMounted error"),
        }

        fs.mount().await.unwrap();
        let stats = fs.stats().unwrap();
        assert_eq!(stats.block_size, block_size);
    }

    #[test_case]
    async fn test_file_operations() {
        let fs = create_test_fs().await;

        let test_content = b"Hello, world!";
        let file_path = "/test.txt";
        let mode = FileMode::REG | FileMode::UREAD | FileMode::UWRITE;

        let file_node = fs.create_file(file_path, mode).await.unwrap();
        assert!(file_node.is_file());

        let bytes_written = fs.write_file(file_path, test_content).await.unwrap();
        assert_eq!(bytes_written, test_content.len());

        let content = fs.read_file(file_path).await.unwrap();
        assert_eq!(content, test_content);

        let new_content = b"New content";
        let bytes_written = fs.write_file(file_path, new_content).await.unwrap();
        assert_eq!(bytes_written, new_content.len());

        let mut buffer = vec![0; new_content.len()];
        let bytes_read = file_node.read_at(0, &mut buffer).await.unwrap();
        assert_eq!(bytes_read, new_content.len());
        assert_eq!(buffer, new_content);

        file_node.truncate(new_content.len() as u64).await.unwrap();

        let content = fs.read_file(file_path).await.unwrap();
        assert_eq!(content, new_content);

        let second_path = "/second.txt";
        fs.create_file(second_path, mode).await.unwrap();

        let root_entries = fs.read_dir("/").await.unwrap();
        assert!(root_entries.iter().any(|e| e.name == "test.txt"));
        assert!(root_entries.iter().any(|e| e.name == "second.txt"));

        fs.remove(file_path).await.unwrap();

        let root_entries = fs.read_dir("/").await.unwrap();
        assert!(!root_entries.iter().any(|e| e.name == "test.txt"));
        assert!(root_entries.iter().any(|e| e.name == "second.txt"));

        match fs.remove(file_path).await {
            Err(FilesystemError::NotFound) => {}
            _ => panic!("Expected NotFound error"),
        }

        fs.remove(second_path).await.unwrap();
    }

    #[test_case]
    async fn test_directory_operations() {
        let fs = create_test_fs().await;

        let dir_path = "/testdir";
        let subdir_path = "/testdir/subdir";
        let mode = FileMode::UREAD | FileMode::UWRITE | FileMode::UEXEC;

        let dir_node = fs.create_directory(dir_path, mode).await.unwrap();
        assert!(dir_node.is_directory());

        let subdir_node = fs.create_directory(subdir_path, mode).await.unwrap();
        assert!(subdir_node.is_directory());

        let root_entries = fs.read_dir("/").await.unwrap();
        assert!(root_entries.iter().any(|e| e.name == "testdir"));

        let dir_entries = fs.read_dir(dir_path).await.unwrap();
        assert!(dir_entries.iter().any(|e| e.name == "subdir"));
        assert!(dir_entries.iter().any(|e| e.name == "."));
        assert!(dir_entries.iter().any(|e| e.name == ".."));

        let file_path = "/testdir/subdir/file.txt";
        let file_mode = FileMode::REG | FileMode::UREAD | FileMode::UWRITE;
        fs.create_file(file_path, file_mode).await.unwrap();

        let subdir_entries = fs.read_dir(subdir_path).await.unwrap();
        assert!(subdir_entries.iter().any(|e| e.name == "file.txt"));

        let content = b"Test file in subdirectory";
        fs.write_file(file_path, content).await.unwrap();

        let read_content = fs.read_file(file_path).await.unwrap();
        assert_eq!(read_content, content);

        match fs.remove(subdir_path).await {
            Err(FilesystemError::NodeError(_)) => {}
            _ => panic!("Expected NotEmpty error"),
        }

        fs.remove(file_path).await.unwrap();

        fs.remove(subdir_path).await.unwrap();

        let dir_entries = fs.read_dir(dir_path).await.unwrap();
        assert!(!dir_entries.iter().any(|e| e.name == "subdir"));

        fs.remove(dir_path).await.unwrap();

        let root_entries = fs.read_dir("/").await.unwrap();
        assert!(!root_entries.iter().any(|e| e.name == "testdir"));
    }

    #[test_case]
    async fn test_large_file_operations() {
        let fs = create_test_fs().await;

        let file_path = "/large.bin";
        let mode = FileMode::REG | FileMode::UREAD | FileMode::UWRITE;
        fs.create_file(file_path, mode).await.unwrap();

        let block_size = fs.stats().unwrap().block_size;

        let data_size = block_size as usize * 32 + 512; // 32.5 blocks
        let mut data = vec![0u8; data_size];

        // Fill with pattern
        for i in 0..data_size {
            data[i] = (i % 256) as u8;
        }

        let bytes_written = fs.write_file(file_path, &data).await.unwrap();
        assert_eq!(bytes_written, data_size);

        let read_data = fs.read_file(file_path).await.unwrap();
        assert_eq!(read_data.len(), data_size);
        assert_eq!(read_data, data);

        let node = fs.get_node(file_path).await.unwrap();

        let mut buffer = vec![0u8; block_size as usize];
        let bytes_read = node.read_at(0, &mut buffer).await.unwrap();
        assert_eq!(bytes_read, block_size as usize);
        assert_eq!(buffer, &data[0..block_size as usize]);

        let offset = block_size as u64 * 2 - 100;
        let size = 200;
        let mut buffer = vec![0u8; size];
        let bytes_read = node.read_at(offset, &mut buffer).await.unwrap();
        assert_eq!(bytes_read, size);
        assert_eq!(buffer, &data[offset as usize..(offset as usize + size)]);

        let mut buffer = vec![0u8; 100];
        let bytes_read = node
            .read_at(data_size as u64 + 100, &mut buffer)
            .await
            .unwrap();
        assert_eq!(bytes_read, 0);

        fs.remove(file_path).await.unwrap();
    }

    #[test_case]
    async fn test_error_cases() {
        let fs = create_test_fs().await;

        match fs.get_node("").await {
            Err(FilesystemError::InvalidPath) => {}
            _ => panic!("Expected InvalidPath error"),
        }

        match fs.get_node("/nonexistent").await {
            Err(FilesystemError::NotFound) => {}
            _ => panic!("Expected NotFound error"),
        }

        let file_path = "/test.txt";
        let mode = FileMode::REG | FileMode::UREAD | FileMode::UWRITE;
        fs.create_file(file_path, mode).await.unwrap();

        match fs.create_file(file_path, mode).await {
            Err(FilesystemError::NodeError(_)) => {}
            _ => panic!("Expected AlreadyExists error"),
        }

        match fs.create_directory(file_path, mode).await {
            Err(FilesystemError::NodeError(_)) => {}
            _ => panic!("Expected AlreadyExists error"),
        }

        match fs.read_dir(file_path).await {
            Err(FilesystemError::NodeError(_)) => {}
            _ => panic!("Expected NotDirectory error"),
        }

        fs.remove(file_path).await.unwrap();
    }

    #[test_case]
    async fn test_file_naming() {
        let fs = create_test_fs().await;
        let mode = FileMode::REG | FileMode::UREAD | FileMode::UWRITE;

        let names = [
            "normal.txt",
            "with spaces.txt",
            "with-dash.txt",
            "with_underscore.txt",
            "with.multiple.dots.txt",
            "UPPERCASE.TXT",
            "MixedCase.Txt",
            "very_long_filename_that_approaches_the_limit_but_should_still_work_fine_in_most_cases.txt",
        ];

        for name in names.iter() {
            let path = format!("/{}", name);
            fs.create_file(&path, mode).await.unwrap();

            let node = fs.get_node(&path).await.unwrap();
            assert!(node.is_file());

            let content = format!("Content for {}", name);
            fs.write_file(&path, content.as_bytes()).await.unwrap();
            let read_content = fs.read_file(&path).await.unwrap();
            assert_eq!(read_content, content.as_bytes());
        }

        let long_name = "a".repeat(256);
        let long_path = format!("/{}", long_name);
        match fs.create_file(&long_path, mode).await {
            Err(FilesystemError::InvalidPath) | Err(FilesystemError::NodeError(_)) => {}
            _ => panic!("Expected error for too long filename"),
        }

        let entries = fs.read_dir("/").await.unwrap();
        for name in names.iter() {
            assert!(entries.iter().any(|e| e.name == *name));
        }

        for name in names.iter() {
            let path = format!("/{}", name);
            fs.remove(&path).await.unwrap();
        }
    }

    #[test_case]
    async fn test_deep_directory_hierarchy() {
        let fs = create_test_fs().await;
        let dir_mode = FileMode::UREAD | FileMode::UWRITE | FileMode::UEXEC;
        let file_mode = FileMode::REG | FileMode::UREAD | FileMode::UWRITE;

        let mut current_path = String::from("");
        let depth = 5;

        for i in 1..=depth {
            current_path = format!("{}/dir{}", current_path, i);
            fs.create_directory(&current_path, dir_mode).await.unwrap();

            let file_path = format!("{}/file{}.txt", current_path, i);
            fs.create_file(&file_path, file_mode).await.unwrap();

            let content = format!("Content for level {}", i);
            fs.write_file(&file_path, content.as_bytes()).await.unwrap();
        }

        let deepest_file = format!("{}/file{}.txt", current_path, depth);
        let content = fs.read_file(&deepest_file).await.unwrap();
        assert_eq!(content, format!("Content for level {}", depth).as_bytes());

        for i in (1..=3).rev() {
            let dir_path = if i == 1 {
                "/dir1".to_string()
            } else if i == 2 {
                "/dir1/dir2".to_string()
            } else {
                "/dir1/dir2/dir3".to_string()
            };

            let entries = fs.read_dir(&dir_path).await.unwrap();
            if i < depth {
                assert!(entries.iter().any(|e| e.name == format!("dir{}", i + 1)));
            }
            assert!(entries.iter().any(|e| e.name == format!("file{}.txt", i)));
        }

        for i in (1..=depth).rev() {
            let dir_path = if i == 1 {
                "/dir1".to_string()
            } else {
                let mut path = String::from("/dir1");
                for j in 2..=i {
                    path = format!("{}/dir{}", path, j);
                }
                path
            };

            let file_path = format!("{}/file{}.txt", dir_path, i);
            fs.remove(&file_path).await.unwrap();

            if i > 1 {
                fs.remove(&dir_path).await.unwrap();
            }
        }

        fs.remove("/dir1").await.unwrap();
    }

    #[test_case]
    async fn test_sparse_files() {
        let fs = create_test_fs().await;
        let mode = FileMode::REG | FileMode::UREAD | FileMode::UWRITE;

        let file_path = "/sparse.bin";
        fs.create_file(file_path, mode).await.unwrap();

        let node = fs.get_node(file_path).await.unwrap();

        let start_data = b"Start of file";
        node.write_at(0, start_data).await.unwrap();

        let offset = 10000; // 10KB offset
        let end_data = b"End of file";
        node.write_at(offset, end_data).await.unwrap();

        let content = fs.read_file(file_path).await.unwrap();

        assert_eq!(&content[0..start_data.len()], start_data);
        assert_eq!(
            &content[offset as usize..(offset as usize + end_data.len())],
            end_data
        );

        assert_eq!(content.len(), offset as usize + end_data.len());

        for i in start_data.len()..offset as usize {
            assert_eq!(content[i], 0);
        }

        fs.remove(file_path).await.unwrap();
    }

    #[test_case]
    async fn test_cache_performance() {
        let fs = create_test_fs().await;
        let mode = FileMode::REG | FileMode::UREAD | FileMode::UWRITE;

        let file_path = "/cache_test.bin";
        fs.create_file(file_path, mode).await.unwrap();

        let block_size = fs.stats().unwrap().block_size;
        let data_size = block_size as usize * 4;
        let mut data = vec![0u8; data_size];
        for i in 0..data_size {
            data[i] = (i % 256) as u8;
        }

        fs.write_file(file_path, &data).await.unwrap();

        let initial_stats = fs.stats().unwrap();
        let initial_block_hits = initial_stats.block_cache_stats.get_hits();
        let initial_inode_hits = initial_stats.inode_cache_stats.get_hits();

        for _ in 0..5 {
            let content = fs.read_file(file_path).await.unwrap();
            assert_eq!(content, data);
        }

        let final_stats = fs.stats().unwrap();
        assert!(final_stats.block_cache_stats.get_hits() > initial_block_hits);
        assert!(final_stats.inode_cache_stats.get_hits() > initial_inode_hits);

        fs.remove(file_path).await.unwrap();
    }
}
