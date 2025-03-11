use super::{
    error::Error,
    messages::Message,
    spsc::{Receiver, Sender},
    spsc_pool::ChannelPool,
};
use crate::{
    events::{spawn, yield_now, JoinHandle},
    serial_println,
};
use alloc::{collections::BTreeMap, sync::Arc};
use bytes::Bytes;
use core::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use futures::channel::oneshot;
use spin::Mutex;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct MountId(pub u32);

struct PendingRequest {
    response_tx: oneshot::Sender<Message>, // Store the oneshot sender for the Message
}

struct Mount {
    _mount_id: MountId,
    tx: Sender<Bytes>,
    pending: Arc<Mutex<BTreeMap<u16, PendingRequest>>>,
    next_tag: AtomicU16,
    task: JoinHandle<()>,
}

impl Mount {
    fn new(_mount_id: MountId, tx: Sender<Bytes>, rx: Receiver<Bytes>) -> Self {
        let pending = Arc::new(Mutex::new(BTreeMap::<u16, PendingRequest>::new()));
        let pending_clone = pending.clone();
        serial_println!("Spawning task");
        let task = spawn(
            0,
            async move {
                loop {
                    yield_now().await;
                    match rx.try_recv() {
                        Ok(response) => match Message::parse(response) {
                            Ok((msg, tag)) => {
                                if let Some(pending_req) = pending_clone.lock().remove(&tag) {
                                    let _ = pending_req.response_tx.send(msg);
                                }
                            }
                            Err(e) => {
                                log::error!("Failed to parse message: {}", e);
                                continue;
                            }
                        },
                        Err(_) => continue,
                    }
                }
            },
            1,
        );
        serial_println!("Done");

        Mount {
            _mount_id,
            tx,
            pending,
            next_tag: AtomicU16::new(0),
            task,
        }
    }

    async fn send_request(&self, _fid: u32, data: Message) -> Result<Message, Error> {
        let tag = self.next_tag.fetch_add(1, Ordering::Relaxed);

        let (response_tx, response_rx) = oneshot::channel();

        self.pending
            .lock()
            .insert(tag, PendingRequest { response_tx });

        self.tx
            .send(data.serialize().unwrap())
            .await
            .map_err(|_| Error::ChannelFull)?;

        response_rx.await.map_err(|_| Error::NoResponse)
    }
}

pub struct MountManager {
    mounts: Mutex<BTreeMap<MountId, Mount>>,
    channel_pool: ChannelPool<Bytes>,
    next_mount_id: AtomicU32,
}

impl MountManager {
    pub fn new(pool_size: usize) -> Self {
        Self {
            mounts: Mutex::new(BTreeMap::new()),
            channel_pool: ChannelPool::new(pool_size),
            next_mount_id: AtomicU32::new(0),
        }
    }

    pub async fn create_mount(&self) -> Result<(MountId, Receiver<Bytes>, Sender<Bytes>), Error> {
        let ((client_tx, server_rx), (server_tx, client_rx)) = self
            .channel_pool
            .allocate_pair()
            .map_err(|_| Error::NoMount)?;

        serial_println!("Got channels");
        let mount_id = MountId(self.next_mount_id.fetch_add(1, Ordering::Relaxed));
        serial_println!("Added stuff");
        let mount = Mount::new(mount_id, client_tx, client_rx);
        serial_println!("Mount spawned");

        self.mounts.lock().insert(mount_id, mount);

        Ok((mount_id, server_rx, server_tx))
    }

    pub async fn send_request(
        &self,
        mount_id: MountId,
        fid: u32,
        data: Message,
    ) -> Result<Message, Error> {
        let mounts = self.mounts.lock();
        let mount = mounts.get(&mount_id).ok_or(Error::InvalidMount)?;

        mount.send_request(fid, data).await
    }

    pub async fn cleanup_mount(&self, mount_id: MountId) -> Result<(), Error> {
        let mut mounts = self.mounts.lock();
        if let Some(m) = mounts.remove(&mount_id) {
            m.task.cancel();
            Ok(())
        } else {
            Err(Error::InvalidMount)
        }
    }
}
