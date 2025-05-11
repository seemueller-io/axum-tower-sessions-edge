use async_trait::async_trait;
use std::fmt::Debug;
use time::OffsetDateTime;
use tower_sessions::{
    session::{Id, Record},
    session_store, SessionStore,
};
use worker::console_error;
use worker::kv::KvStore;

#[derive(Clone)]
pub struct CloudflareKvStore {
    kv_storage: KvStore,
}

impl CloudflareKvStore {
    pub(crate) fn new(kv_storage: KvStore) -> Self {
        Self { kv_storage }
    }
}

impl Default for CloudflareKvStore {
    fn default() -> Self {
        Self {
            kv_storage: KvStore::create("KV_STORAGE").expect("Failed to create KV store"),
        }
    }
}

impl std::fmt::Debug for CloudflareKvStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareKvStore").finish_non_exhaustive()
    }
}

#[worker::send]
async fn get_rec(kv_store: KvStore, session_id: String) -> Option<Record> {
    match kv_store.get(&session_id).text().await {
        Ok(record) => {
            serde_json::de::from_str(record.unwrap_or_default().as_str()).unwrap_or_default()
        }
        Err(err) => {
            console_error!("{:?}", err.to_string().as_str());
            None
        }
    }
}

#[worker::send]
async fn delete_rec(kv_store: KvStore, session_id: String) -> Option<()> {
    kv_store
        .delete(&session_id.to_string())
        .await
        .expect("Failed to delete session");
    Some(())
}

#[worker::send]
async fn create_record_handler(kv_storage: KvStore, record: &mut Record) {
    let id = record.id.to_string();
    let serialized_record = serde_json::to_string(record).expect("Failed to serialize record");
    let request = kv_storage
        .put(&id, serialized_record)
        .expect("Failed to create session");
    if let Err(err) = request.execute().await {
        panic!("Failed to execute create request");
    }
}

#[worker::send]
async fn save_record_handler(kv_storage: KvStore, record: &Record) {
    let id = record.id.to_string();
    let serialized_record = serde_json::to_string(record).expect("Failed to serialize record");
    let request = kv_storage.put(&id, serialized_record).unwrap();
    if let Err(err) = request.execute().await {
        panic!("Failed to execute save request");
    }
}

#[async_trait]
impl SessionStore for CloudflareKvStore {
    async fn create(&self, record: &mut Record) -> session_store::Result<()> {
        if record.id.to_string().is_empty() {
            record.id = Id::default();
        }

        create_record_handler(self.kv_storage.clone(), record).await;

        Ok(())
    }

    async fn save(&self, record: &Record) -> session_store::Result<()> {
        save_record_handler(self.kv_storage.clone(), record).await;

        Ok(())
    }

    async fn load(&self, session_id: &Id) -> session_store::Result<Option<Record>> {
        let id = session_id.to_string();

        match get_rec(self.kv_storage.clone(), id).await {
            Some(record) => {
                let is_active = is_active(record.expiry_date);

                if is_active {
                    Ok(Some(record))
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }

    async fn delete(&self, session_id: &Id) -> session_store::Result<()> {
        delete_rec(self.kv_storage.clone(), session_id.to_string())
            .await
            .unwrap();

        Ok(())
    }
}

fn is_active(expiry_date: OffsetDateTime) -> bool {
    expiry_date > OffsetDateTime::now_utc()
}

// #[cfg(test)]
// mod tests {
//     use time::Duration;
//
//     use super::*;
//
//     #[tokio::test]
//     async fn test_create() {
//         let store = CloudflareKvStore::default();
//         let mut record = Record {
//             id: Default::default(),
//             data: Default::default(),
//             expiry_date: OffsetDateTime::now_utc() + Duration::minutes(30),
//         };
//         assert!(store.create(&mut record).await.is_ok());
//     }
//
//     #[tokio::test]
//     async fn test_save() {
//         let store = CloudflareKvStore::default();
//         let record = Record {
//             id: Default::default(),
//             data: Default::default(),
//             expiry_date: OffsetDateTime::now_utc() + Duration::minutes(30),
//         };
//         assert!(store.save(&record).await.is_ok());
//     }
//
//     #[tokio::test]
//     async fn test_load() {
//         let store = CloudflareKvStore::default();
//         let mut record = Record {
//             id: Default::default(),
//             data: Default::default(),
//             expiry_date: OffsetDateTime::now_utc() + Duration::minutes(30),
//         };
//         store.create(&mut record).await.unwrap();
//         let loaded_record = store.load(&record.id).await.unwrap();
//         assert_eq!(Some(record), loaded_record);
//     }
//
//     #[tokio::test]
//     async fn test_delete() {
//         let store = CloudflareKvStore::default();
//         let mut record = Record {
//             id: Default::default(),
//             data: Default::default(),
//             expiry_date: OffsetDateTime::now_utc() + Duration::minutes(30),
//         };
//         store.create(&mut record).await.unwrap();
//         assert!(store.delete(&record.id).await.is_ok());
//         assert_eq!(None, store.load(&record.id).await.unwrap());
//     }
//
//     #[tokio::test]
//     async fn test_create_id_collision() {
//         let store = CloudflareKvStore::default();
//         let expiry_date = OffsetDateTime::now_utc() + Duration::minutes(30);
//         let mut record1 = Record {
//             id: Default::default(),
//             data: Default::default(),
//             expiry_date,
//         };
//         let mut record2 = Record {
//             id: Default::default(),
//             data: Default::default(),
//             expiry_date,
//         };
//         store.create(&mut record1).await.unwrap();
//         record2.id = record1.id; // Set the same ID for record2
//         store.create(&mut record2).await.unwrap();
//         assert_ne!(record1.id, record2.id); // IDs should be different
//     }
// }
