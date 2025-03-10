use super::{
    error::Error,
    messages::Message,
    mnt_manager,
    mount_manager::MountId,
    requests::{Tattach, Tclunk, Twalk},
};
use alloc::{collections::BTreeMap, string::String, vec};
use bytes::Bytes;
use core::sync::atomic::{AtomicU32, Ordering};

#[derive(Clone, Debug)]
struct DirEntry {
    _name: String,
    mount_id: Option<usize>,
    children: BTreeMap<String, DirEntry>,
}

#[derive(Debug)]
pub struct PathResolution {
    pub mount_id: usize,
    pub fid: u32,
}

#[derive(Debug)]
pub struct Namespace {
    root: DirEntry,
    next_fid: AtomicU32,
}

const ROOTFID: u32 = 0;

impl Default for Namespace {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for Namespace {
    fn clone(&self) -> Self {
        Namespace {
            root: self.root.clone(),
            next_fid: AtomicU32::new(self.next_fid.load(Ordering::Relaxed))
        }
    }
}

impl Namespace {
    pub fn new() -> Self {
        Self {
            root: DirEntry {
                _name: "/".into(),
                mount_id: None,
                children: BTreeMap::new(),
            },
            next_fid: AtomicU32::new(1), // 0 is reserved for root
        }
    }

    pub async fn walk_path(&self, path: &str) -> Result<PathResolution, Error> {
        if path.is_empty() {
            return Err(Error::InvalidPath);
        }

        let components: vec::Vec<String> = path
            .split('/')
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();

        if components.len() > 255 {
            return Err(Error::TooManyComponents);
        }

        let mut current = &self.root;
        let mut current_fid = ROOTFID;
        let mut current_mount = None;

        // Walk the path components
        for component in components {
            // If we hit a new mount point
            if current.mount_id != current_mount {
                if let Some(mount_id) = current.mount_id {
                    // Need to attach to the new mount
                    let new_fid = self.next_fid.fetch_add(1, Ordering::Relaxed);
                    let msg = Message::Tattach(
                        Tattach::new(0, new_fid, 0, Bytes::new(), Bytes::new()).unwrap(),
                    );

                    let response = mnt_manager
                        .send_request(MountId(mount_id as u32), new_fid, msg)
                        .await?;

                    match response {
                        Message::Rattach(_) => {
                            current_fid = new_fid;
                            current_mount = Some(mount_id);
                        }
                        _ => return Err(Error::Protocol),
                    }
                }
            }

            // Now walk this component
            if let Some(mount_id) = current_mount {
                // We're in a mount point - do a 9P walk
                let new_fid = self.next_fid.fetch_add(1, Ordering::Relaxed);
                let v = vec![Bytes::copy_from_slice(component.as_bytes())];
                let msg = Message::Twalk(Twalk::new(0, current_fid, new_fid, v).unwrap());

                let response = mnt_manager
                    .send_request(MountId(mount_id as u32), new_fid, msg)
                    .await?;

                match response {
                    Message::Rwalk(_) => {
                        current_fid = new_fid;
                    }
                    _ => return Err(Error::NotFound),
                }
            }

            // Update our position in directory tree
            match current.children.get(&component) {
                Some(entry) => current = entry,
                None => return Err(Error::NotFound),
            }
        }

        // Return final mount point and fid
        if let Some(mount_id) = current_mount {
            Ok(PathResolution {
                mount_id,
                fid: current_fid,
            })
        } else {
            Err(Error::NoMount)
        }
    }

    pub async fn add_mount(&mut self, path: &str, mount_id: usize) -> Result<(), Error> {
        if path.is_empty() || !path.starts_with('/') {
            return Err(Error::InvalidPath);
        }

        let components: vec::Vec<String> = path
            .split('/')
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();

        if components.is_empty() {
            return Err(Error::InvalidPath);
        }

        let mut current = &mut self.root;

        // Create/traverse path components
        for component in components {
            current = current
                .children
                .entry(component.clone())
                .or_insert_with(|| DirEntry {
                    _name: component,
                    mount_id: None,
                    children: BTreeMap::new(),
                });
        }

        // Check if already mounted
        if current.mount_id.is_some() {
            return Err(Error::AlreadyMounted);
        }

        // Try to attach to verify mount works
        let fid = self.next_fid.fetch_add(1, Ordering::Relaxed);
        let msg = Message::Tattach(Tattach::new(0, fid, 0, Bytes::new(), Bytes::new()).unwrap());

        let response = mnt_manager
            .send_request(MountId(mount_id as u32), fid, msg)
            .await?;

        match response {
            Message::Rattach(_) => {
                // Mount works - record it
                current.mount_id = Some(mount_id);
                Ok(())
            }
            _ => Err(Error::InvalidMount),
        }
    }

    pub async fn remove_mount(&mut self, path: &str) -> Result<(), Error> {
        if path.is_empty() || !path.starts_with('/') {
            return Err(Error::InvalidPath);
        }

        let components: vec::Vec<String> = path
            .split('/')
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();

        let mut current = &mut self.root;

        // Walk to mount point
        for component in &components[..components.len() - 1] {
            current = current.children.get_mut(component).ok_or(Error::NotFound)?;
        }

        let last = &components[components.len() - 1];
        let entry = current.children.get_mut(last).ok_or(Error::NotFound)?;

        // Check it's actually a mount
        let mount_id = entry.mount_id.ok_or(Error::NotMount)?;

        // Send clunk for root fid
        let msg = Message::Tclunk(Tclunk::new(0, ROOTFID).unwrap());

        let response = mnt_manager
            .send_request(MountId(mount_id as u32), ROOTFID, msg)
            .await?;

        match response {
            Message::Rclunk(_) => {
                // Remove mount point
                entry.mount_id = None;

                // Clean up mount in manager
                mnt_manager.cleanup_mount(MountId(mount_id as u32)).await?;

                Ok(())
            }
            _ => Err(Error::Protocol),
        }
    }
}
