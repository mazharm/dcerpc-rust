//! Single-Threaded Apartment (STA) implementation
//!
//! In an STA, all calls are serialized through a message queue.
//! Objects don't need to be thread-safe.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::sync::atomic::{AtomicBool, Ordering};
use bytes::Bytes;
use tokio::sync::{mpsc, oneshot};
use crate::types::{Oid, DcomError};
use super::apartment::{Apartment, ApartmentId, ApartmentType, CallFuture, CallResult, ComObject};

/// Message for the STA message queue
struct StaMessage {
    /// Object ID
    oid: Oid,
    /// Interface IID
    iid: dcerpc::Uuid,
    /// Operation number
    opnum: u16,
    /// Arguments
    args: Bytes,
    /// Response channel
    response: oneshot::Sender<CallResult>,
}

/// Single-Threaded Apartment
///
/// All calls are serialized through a message queue and executed
/// on a dedicated thread. Objects don't need to be thread-safe.
pub struct SinglethreadedApartment {
    /// Apartment ID
    id: ApartmentId,
    /// Registered objects by OID
    objects: Arc<RwLock<HashMap<Oid, Arc<dyn ComObject>>>>,
    /// Message sender
    sender: Mutex<Option<mpsc::Sender<StaMessage>>>,
    /// Running flag
    running: AtomicBool,
}

impl SinglethreadedApartment {
    /// Create a new STA (starts the message loop)
    pub fn new() -> Self {
        let sta = Self {
            id: ApartmentId::generate(),
            objects: Arc::new(RwLock::new(HashMap::new())),
            sender: Mutex::new(None),
            running: AtomicBool::new(true),
        };

        sta.start_message_loop();
        sta
    }

    /// Create with a specific ID
    pub fn with_id(id: ApartmentId) -> Self {
        let sta = Self {
            id,
            objects: Arc::new(RwLock::new(HashMap::new())),
            sender: Mutex::new(None),
            running: AtomicBool::new(true),
        };

        sta.start_message_loop();
        sta
    }

    /// Start the message processing loop
    fn start_message_loop(&self) {
        let (tx, mut rx) = mpsc::channel::<StaMessage>(1024);
        *self.sender.lock().unwrap() = Some(tx);

        let objects = self.objects.clone();
        let running = self.running.load(Ordering::SeqCst);

        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if !running {
                    let _ = msg.response.send(Err(DcomError::ApartmentError(
                        "apartment shutdown".to_string(),
                    )));
                    continue;
                }

                let result = {
                    let objects_guard = objects.read().unwrap();
                    if let Some(obj) = objects_guard.get(&msg.oid) {
                        // Execute the call synchronously in this task
                        Some(obj.invoke(&msg.iid, msg.opnum, msg.args))
                    } else {
                        None
                    }
                };

                let call_result = match result {
                    Some(future) => future.await,
                    None => Err(DcomError::ObjectNotFound(msg.oid.0)),
                };

                let _ = msg.response.send(call_result);
            }
        });
    }
}

impl Default for SinglethreadedApartment {
    fn default() -> Self {
        Self::new()
    }
}

impl Apartment for SinglethreadedApartment {
    fn id(&self) -> ApartmentId {
        self.id
    }

    fn apartment_type(&self) -> ApartmentType {
        ApartmentType::Sta
    }

    fn register_object(&self, object: Arc<dyn ComObject>) -> Oid {
        let oid = object.oid();
        let mut objects = self.objects.write().unwrap();
        objects.insert(oid, object);
        oid
    }

    fn get_object(&self, oid: &Oid) -> Option<Arc<dyn ComObject>> {
        let objects = self.objects.read().unwrap();
        objects.get(oid).cloned()
    }

    fn dispatch(
        &self,
        oid: Oid,
        iid: dcerpc::Uuid,
        opnum: u16,
        args: Bytes,
    ) -> CallFuture {
        if !self.running.load(Ordering::SeqCst) {
            return Box::pin(async move {
                Err(DcomError::ApartmentError("apartment is shutdown".to_string()))
            });
        }

        let sender = {
            let guard = self.sender.lock().unwrap();
            guard.clone()
        };

        match sender {
            Some(tx) => {
                let (response_tx, response_rx) = oneshot::channel();
                let msg = StaMessage {
                    oid,
                    iid,
                    opnum,
                    args,
                    response: response_tx,
                };

                Box::pin(async move {
                    tx.send(msg)
                        .await
                        .map_err(|_| DcomError::ApartmentError("failed to send message".to_string()))?;

                    response_rx
                        .await
                        .map_err(|_| DcomError::ApartmentError("failed to receive response".to_string()))?
                })
            }
            None => {
                Box::pin(async move {
                    Err(DcomError::ApartmentError("apartment not initialized".to_string()))
                })
            }
        }
    }

    fn shutdown(&self) {
        self.running.store(false, Ordering::SeqCst);
        *self.sender.lock().unwrap() = None;
        let mut objects = self.objects.write().unwrap();
        objects.clear();
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;
    use std::sync::atomic::AtomicUsize;

    struct CountingObject {
        oid: Oid,
        call_count: AtomicUsize,
    }

    impl ComObject for CountingObject {
        fn oid(&self) -> Oid {
            self.oid
        }

        fn supported_interfaces(&self) -> Vec<dcerpc::Uuid> {
            vec![dcerpc::Uuid::NIL]
        }

        fn invoke(
            &self,
            _iid: &dcerpc::Uuid,
            _opnum: u16,
            _args: Bytes,
        ) -> CallFuture {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(Bytes::new()) })
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    #[tokio::test]
    async fn test_sta_basic() {
        let sta = SinglethreadedApartment::new();
        let obj = Arc::new(CountingObject {
            oid: Oid::generate(),
            call_count: AtomicUsize::new(0),
        });
        let oid = obj.oid();

        sta.register_object(obj.clone());

        // Make several calls
        for _ in 0..5 {
            let result = sta
                .dispatch(oid, dcerpc::Uuid::NIL, 0, Bytes::new())
                .await;
            assert!(result.is_ok());
        }

        // All calls should have been processed
        assert_eq!(obj.call_count.load(Ordering::SeqCst), 5);
    }
}
