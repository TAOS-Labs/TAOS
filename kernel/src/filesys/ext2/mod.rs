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
    use alloc::{string::String, sync::Arc, vec, vec::Vec};

    use crate::devices::sd_card::SD_CARD;

    use super::{
        block_io::BlockIO,
        filesystem::{Ext2, FilesystemError},
        structures::{FileMode, FileType},
    };

    const MEDIUM_FILE: &[u8] = include_bytes!("../../../../resources/fonts/Comfortaa-Regular.ttf");

    // Helper function to create a test filesystem using the SD card
    async fn create_test_fs() -> Arc<Ext2> {
        let sd_card_lock = SD_CARD.lock();
        let sd_card = sd_card_lock.clone().unwrap();
        let sd_arc = Arc::new(sd_card);
        let fs = Ext2::new(sd_arc).await.unwrap();
        fs.mount().await.unwrap();
        fs
    }

    // Test reading a medium-sized file
    #[test_case]
    async fn test_read_medium_file() {
        let fs = create_test_fs().await;
        let file = fs.read_file("/fonts/Comfortaa-Regular.ttf").await.unwrap();
        assert!(file == MEDIUM_FILE);
    }

    // Basic mounting and unmounting tests
    #[test_case]
    async fn test_mount_unmount() {
        let fs = create_test_fs().await;

        // Get block size from mounted filesystem
        let block_size = fs.stats().unwrap().block_size;

        // Test unmounting
        fs.unmount().await.unwrap();

        // Operations should fail when unmounted
        match fs.read_file("/test.txt").await {
            Err(FilesystemError::NotMounted) => {}
            _ => panic!("Expected NotMounted error"),
        }

        // Remounting should work
        fs.mount().await.unwrap();
        let stats = fs.stats().unwrap();
        assert_eq!(stats.block_size, block_size);
    }

    // File operations tests
    #[test_case]
    async fn test_file_operations() {
        let fs = create_test_fs().await;

        // Create a file
        let test_content = b"Hello, world!";
        let file_path = "/test.txt";
        let mode = FileMode::REG | FileMode::UREAD | FileMode::UWRITE;

        let file_node = fs.create_file(file_path, mode).await.unwrap();
        assert!(file_node.is_file());

        // Write to file
        let bytes_written = fs.write_file(file_path, test_content).await.unwrap();
        assert_eq!(bytes_written, test_content.len());

        // Read the file
        let content = fs.read_file(file_path).await.unwrap();
        assert_eq!(content, test_content);

        // Overwrite the file with new content
        let new_content = b"New content";
        let bytes_written = fs.write_file(file_path, new_content).await.unwrap();
        assert_eq!(bytes_written, new_content.len());

        // Read updated content
        let content = fs.read_file(file_path).await.unwrap();
        assert_eq!(content, new_content);

        // Create another file
        let second_path = "/second.txt";
        fs.create_file(second_path, mode).await.unwrap();

        // Check that both files exist
        let root_entries = fs.read_dir("/").await.unwrap();
        assert!(root_entries.iter().any(|e| e.name == "test.txt"));
        assert!(root_entries.iter().any(|e| e.name == "second.txt"));

        // Remove a file
        fs.remove(file_path).await.unwrap();

        // Check file is removed
        let root_entries = fs.read_dir("/").await.unwrap();
        assert!(!root_entries.iter().any(|e| e.name == "test.txt"));
        assert!(root_entries.iter().any(|e| e.name == "second.txt"));

        // Removing again should fail
        match fs.remove(file_path).await {
            Err(FilesystemError::NotFound) => {}
            _ => panic!("Expected NotFound error"),
        }

        // Clean up
        fs.remove(second_path).await.unwrap();
    }

    // Directory operations tests
    /*#[test_case]
    async fn test_directory_operations() {
        let fs = create_test_fs().await;

        // Create directories
        let dir_path = "/testdir";
        let subdir_path = "/testdir/subdir";
        let mode = FileMode::UREAD | FileMode::UWRITE | FileMode::UEXEC;

        let dir_node = fs.create_directory(dir_path, mode).await.unwrap();
        assert!(dir_node.is_directory());

        // Create a subdirectory
        let subdir_node = fs.create_directory(subdir_path, mode).await.unwrap();
        assert!(subdir_node.is_directory());

        // List the root directory
        let root_entries = fs.read_dir("/").await.unwrap();
        assert!(root_entries.iter().any(|e| e.name == "testdir"));

        // List the test directory
        let dir_entries = fs.read_dir(dir_path).await.unwrap();
        assert!(dir_entries.iter().any(|e| e.name == "subdir"));
        assert!(dir_entries.iter().any(|e| e.name == ".")); // Should have . entry
        assert!(dir_entries.iter().any(|e| e.name == "..")); // Should have .. entry

        // Create a file in the subdirectory
        let file_path = "/testdir/subdir/file.txt";
        let file_mode = FileMode::REG | FileMode::UREAD | FileMode::UWRITE;
        fs.create_file(file_path, file_mode).await.unwrap();

        // Check file exists in subdir
        let subdir_entries = fs.read_dir(subdir_path).await.unwrap();
        assert!(subdir_entries.iter().any(|e| e.name == "file.txt"));

        // Write to the file
        let content = b"Test file in subdirectory";
        fs.write_file(file_path, content).await.unwrap();

        // Read from the file
        let read_content = fs.read_file(file_path).await.unwrap();
        assert_eq!(read_content, content);

        // Try to remove non-empty directory (should fail)
        match fs.remove(subdir_path).await {
            Err(FilesystemError::NodeError(_)) => {} // Should be NodeError::NotEmpty
            _ => panic!("Expected NotEmpty error"),
        }

        // Remove the file first
        fs.remove(file_path).await.unwrap();

        // Now remove the empty subdirectory
        fs.remove(subdir_path).await.unwrap();

        // Check subdir is gone
        let dir_entries = fs.read_dir(dir_path).await.unwrap();
        assert!(!dir_entries.iter().any(|e| e.name == "subdir"));

        // Remove the main directory
        fs.remove(dir_path).await.unwrap();

        // Check dir is gone from root
        let root_entries = fs.read_dir("/").await.unwrap();
        assert!(!root_entries.iter().any(|e| e.name == "testdir"));
    }

    // Large file and stress tests
    #[test_case]
    async fn test_large_file_operations() {
        let fs = create_test_fs().await;

        // Create a large file (multiple blocks)
        let file_path = "/large.bin";
        let mode = FileMode::REG | FileMode::UREAD | FileMode::UWRITE;
        fs.create_file(file_path, mode).await.unwrap();

        // Get block size from filesystem
        let block_size = fs.stats().unwrap().block_size;

        // Create data larger than block size
        let data_size = block_size as usize * 3 + 512; // 3.5 blocks
        let mut data = vec![0u8; data_size];

        // Fill with pattern
        for i in 0..data_size {
            data[i] = (i % 256) as u8;
        }

        // Write large data
        let bytes_written = fs.write_file(file_path, &data).await.unwrap();
        assert_eq!(bytes_written, data_size);

        // Read it back
        let read_data = fs.read_file(file_path).await.unwrap();
        assert_eq!(read_data.len(), data_size);
        assert_eq!(read_data, data);

        // Test reading portions of the file
        let node = fs.get_node(file_path).await.unwrap();

        // Read first block
        let mut buffer = vec![0u8; block_size as usize];
        let bytes_read = node.read_at(0, &mut buffer).await.unwrap();
        assert_eq!(bytes_read, block_size as usize);
        assert_eq!(buffer, &data[0..block_size as usize]);

        // Read from middle (crossing block boundary)
        let offset = block_size as u64 * 2 - 100;
        let size = 200;
        let mut buffer = vec![0u8; size];
        let bytes_read = node.read_at(offset, &mut buffer).await.unwrap();
        assert_eq!(bytes_read, size);
        assert_eq!(buffer, &data[offset as usize..(offset as usize + size)]);

        // Read beyond file size
        let mut buffer = vec![0u8; 100];
        let bytes_read = node
            .read_at(data_size as u64 + 100, &mut buffer)
            .await
            .unwrap();
        assert_eq!(bytes_read, 0); // Should return 0 bytes read

        // Clean up
        fs.remove(file_path).await.unwrap();
    }

    // Error cases and edge conditions
    #[test_case]
    async fn test_error_cases() {
        let fs = create_test_fs().await;

        // Invalid paths
        match fs.get_node("").await {
            Err(FilesystemError::InvalidPath) => {}
            _ => panic!("Expected InvalidPath error"),
        }

        // Non-existent paths
        match fs.get_node("/nonexistent").await {
            Err(FilesystemError::NotFound) => {}
            _ => panic!("Expected NotFound error"),
        }

        // Create a file
        let file_path = "/test.txt";
        let mode = FileMode::REG | FileMode::UREAD | FileMode::UWRITE;
        fs.create_file(file_path, mode).await.unwrap();

        // Try to create file that already exists
        match fs.create_file(file_path, mode).await {
            Err(FilesystemError::NodeError(_)) => {} // Should be NodeError::AlreadyExists
            _ => panic!("Expected AlreadyExists error"),
        }

        // Try to create directory with same name as file
        match fs.create_directory(file_path, mode).await {
            Err(FilesystemError::NodeError(_)) => {} // Should be NodeError::AlreadyExists
            _ => panic!("Expected AlreadyExists error"),
        }

        // Trying to read a file as directory
        match fs.read_dir(file_path).await {
            Err(FilesystemError::NodeError(_)) => {} // Should be NodeError::NotDirectory
            _ => panic!("Expected NotDirectory error"),
        }

        // Clean up
        fs.remove(file_path).await.unwrap();
    }

    // File and directory naming tests
    #[test_case]
    async fn test_file_naming() {
        let fs = create_test_fs().await;
        let mode = FileMode::REG | FileMode::UREAD | FileMode::UWRITE;

        // Test with various valid filenames
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

            // Verify file exists
            let node = fs.get_node(&path).await.unwrap();
            assert!(node.is_file());

            // Write and read test
            let content = format!("Content for {}", name);
            fs.write_file(&path, content.as_bytes()).await.unwrap();
            let read_content = fs.read_file(&path).await.unwrap();
            assert_eq!(read_content, content.as_bytes());
        }

        // Test very long name (should fail)
        let long_name = "a".repeat(256);
        let long_path = format!("/{}", long_name);
        match fs.create_file(&long_path, mode).await {
            Err(FilesystemError::InvalidPath) | Err(FilesystemError::NodeError(_)) => {}
            _ => panic!("Expected error for too long filename"),
        }

        // Check all files in directory
        let entries = fs.read_dir("/").await.unwrap();
        for name in names.iter() {
            assert!(entries.iter().any(|e| e.name == *name));
        }

        // Clean up
        for name in names.iter() {
            let path = format!("/{}", name);
            fs.remove(&path).await.unwrap();
        }
    }

    // Deep directory hierarchy test
    #[test_case]
    async fn test_deep_directory_hierarchy() {
        let fs = create_test_fs().await;
        let dir_mode = FileMode::UREAD | FileMode::UWRITE | FileMode::UEXEC;
        let file_mode = FileMode::REG | FileMode::UREAD | FileMode::UWRITE;

        // Create a deep directory structure
        let mut current_path = String::from("");
        let depth = 5; // Reduced depth to work better with SD card

        for i in 1..=depth {
            current_path = format!("{}/dir{}", current_path, i);
            fs.create_directory(&current_path, dir_mode).await.unwrap();

            // Create a file at each level
            let file_path = format!("{}/file{}.txt", current_path, i);
            fs.create_file(&file_path, file_mode).await.unwrap();

            // Write some content
            let content = format!("Content for level {}", i);
            fs.write_file(&file_path, content.as_bytes()).await.unwrap();
        }

        // Verify deepest file
        let deepest_file = format!("{}/file{}.txt", current_path, depth);
        let content = fs.read_file(&deepest_file).await.unwrap();
        assert_eq!(content, format!("Content for level {}", depth).as_bytes());

        // Navigate back up and check each level
        for i in (1..=3).rev() {
            // Just check first 3 levels
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

        // Clean up - remove from deepest first
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

            // Remove file at this level
            let file_path = format!("{}/file{}.txt", dir_path, i);
            fs.remove(&file_path).await.unwrap();

            // Remove directory if not root level
            if i > 1 {
                fs.remove(&dir_path).await.unwrap();
            }
        }

        // Remove root directory
        fs.remove("/dir1").await.unwrap();
    }

    // Sparse file test
    #[test_case]
    async fn test_sparse_files() {
        let fs = create_test_fs().await;
        let mode = FileMode::REG | FileMode::UREAD | FileMode::UWRITE;

        // Create a file
        let file_path = "/sparse.bin";
        fs.create_file(file_path, mode).await.unwrap();

        let node = fs.get_node(file_path).await.unwrap();

        // Write at the beginning
        let start_data = b"Start of file";
        node.write_at(0, start_data).await.unwrap();

        // Write at an offset (creating a sparse file)
        let offset = 10000; // 10KB offset
        let end_data = b"End of file";
        node.write_at(offset, end_data).await.unwrap();

        // Read the entire file
        let content = fs.read_file(file_path).await.unwrap();

        // Verify the content
        assert_eq!(&content[0..start_data.len()], start_data);
        assert_eq!(
            &content[offset as usize..(offset as usize + end_data.len())],
            end_data
        );

        // Verify the sparse region is zero-filled
        for i in start_data.len()..offset as usize {
            assert_eq!(content[i], 0);
        }

        // Check file size is correct (should be offset + end_data.len())
        assert_eq!(content.len(), offset as usize + end_data.len());

        // Clean up
        fs.remove(file_path).await.unwrap();
    }

    // Cache performance test
    #[test_case]
    async fn test_cache_performance() {
        let fs = create_test_fs().await;
        let mode = FileMode::REG | FileMode::UREAD | FileMode::UWRITE;

        // Create a file and write data
        let file_path = "/cache_test.bin";
        fs.create_file(file_path, mode).await.unwrap();

        let block_size = fs.stats().unwrap().block_size;
        let data_size = block_size as usize * 4; // 4 blocks
        let mut data = vec![0u8; data_size];
        for i in 0..data_size {
            data[i] = (i % 256) as u8;
        }

        fs.write_file(file_path, &data).await.unwrap();

        // Get initial cache stats
        let initial_stats = fs.stats().unwrap();
        let initial_block_hits = initial_stats.block_cache_stats.get_hits();
        let initial_inode_hits = initial_stats.inode_cache_stats.get_hits();

        // Perform multiple reads to test cache
        for _ in 0..5 {
            let content = fs.read_file(file_path).await.unwrap();
            assert_eq!(content, data);
        }

        // Check cache stats after reads
        let final_stats = fs.stats().unwrap();
        assert!(final_stats.block_cache_stats.get_hits() > initial_block_hits);
        assert!(final_stats.inode_cache_stats.get_hits() > initial_inode_hits);

        // Print cache performance stats
        println!(
            "Block cache: hits={}, misses={}, hit ratio={:.2}%",
            final_stats.block_cache_stats.hits,
            final_stats.block_cache_stats.misses,
            100.0 * final_stats.block_cache_stats.hits as f64
                / (final_stats.block_cache_stats.hits + final_stats.block_cache_stats.misses)
                    as f64
        );

        println!(
            "Inode cache: hits={}, misses={}, hit ratio={:.2}%",
            final_stats.inode_cache_stats.hits,
            final_stats.inode_cache_stats.misses,
            100.0 * final_stats.inode_cache_stats.hits as f64
                / (final_stats.inode_cache_stats.hits + final_stats.inode_cache_stats.misses)
                    as f64
        );

        // Clean up
        fs.remove(file_path).await.unwrap();
    }*/
}
