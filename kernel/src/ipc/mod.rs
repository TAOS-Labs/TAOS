use lazy_static::lazy_static;
use mount_manager::MountManager;

// pub mod channel;
pub mod error;
pub mod fd_table;
pub mod messages;
pub mod mount_manager;
pub mod namespace;
pub mod requests;
pub mod responses;
pub mod serialization;
pub mod spsc;
pub mod spsc_pool;

lazy_static! {
    pub static ref mnt_manager: MountManager = MountManager::new(3);
}
