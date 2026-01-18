use std::sync::Arc;

use parking_lot::Mutex;
use postgres::{Client, NoTls};
use serde_json::Value;

use crate::repository::{BusinessRepository, BusinessSnapshot, RepositoryError};

pub struct PgBusinessRepository {
    client: Arc<Mutex<Client>>,
}

impl PgBusinessRepository {
    pub fn connect(dsn: &str) -> Result<Self, RepositoryError> {
        let client =
            Client::connect(dsn, NoTls).map_err(|err| RepositoryError::Store(err.to_string()))?;
        Ok(Self {
            client: Arc::new(Mutex::new(client)),
        })
    }

    pub fn ensure_schema(&self) -> Result<(), RepositoryError> {
        let mut client = self.client.lock();
        client
            .batch_execute(
                "CREATE TABLE IF NOT EXISTS business_snapshot (
                    id INTEGER PRIMARY KEY,
                    snapshot JSONB NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );",
            )
            .map_err(|err| RepositoryError::Store(err.to_string()))?;
        Ok(())
    }
}

impl BusinessRepository for PgBusinessRepository {
    fn load_snapshot(&self) -> Result<BusinessSnapshot, RepositoryError> {
        let mut client = self.client.lock();
        let row = client
            .query_opt("SELECT snapshot FROM business_snapshot WHERE id = 1", &[])
            .map_err(|err| RepositoryError::Store(err.to_string()))?;
        let Some(row) = row else {
            return Ok(BusinessSnapshot::default());
        };
        let value: Value = row
            .try_get(0)
            .map_err(|err| RepositoryError::Serialization(err.to_string()))?;
        serde_json::from_value(value).map_err(|err| RepositoryError::Serialization(err.to_string()))
    }

    fn save_snapshot(&self, snapshot: &BusinessSnapshot) -> Result<(), RepositoryError> {
        let payload =
            serde_json::to_value(snapshot).map_err(|err| RepositoryError::Serialization(err.to_string()))?;
        let mut client = self.client.lock();
        client
            .execute(
                "INSERT INTO business_snapshot (id, snapshot, updated_at)
                 VALUES (1, $1, NOW())
                 ON CONFLICT (id)
                 DO UPDATE SET snapshot = EXCLUDED.snapshot, updated_at = NOW()",
                &[&payload],
            )
            .map_err(|err| RepositoryError::Store(err.to_string()))?;
        Ok(())
    }

    fn is_seeded(&self) -> Result<bool, RepositoryError> {
        let mut client = self.client.lock();
        let row = client
            .query_opt("SELECT 1 FROM business_snapshot WHERE id = 1", &[])
            .map_err(|err| RepositoryError::Store(err.to_string()))?;
        Ok(row.is_some())
    }
}
