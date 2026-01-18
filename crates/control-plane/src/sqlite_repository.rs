use std::sync::Arc;

use parking_lot::Mutex;
use rusqlite::{params, Connection};
use serde_json::Value;

use crate::repository::{BusinessRepository, BusinessSnapshot, RepositoryError};

pub struct SqliteBusinessRepository {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteBusinessRepository {
    pub fn open(path: &str) -> Result<Self, RepositoryError> {
        let conn = Connection::open(path).map_err(|err| RepositoryError::Store(err.to_string()))?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn ensure_schema(&self) -> Result<(), RepositoryError> {
        let conn = self.conn.lock();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS business_snapshot (
                id INTEGER PRIMARY KEY,
                snapshot TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );",
        )
        .map_err(|err| RepositoryError::Store(err.to_string()))?;
        Ok(())
    }
}

impl BusinessRepository for SqliteBusinessRepository {
    fn load_snapshot(&self) -> Result<BusinessSnapshot, RepositoryError> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT snapshot FROM business_snapshot WHERE id = 1")
            .map_err(|err| RepositoryError::Store(err.to_string()))?;
        let mut rows = stmt
            .query([])
            .map_err(|err| RepositoryError::Store(err.to_string()))?;
        let row = match rows.next().map_err(|err| RepositoryError::Store(err.to_string()))? {
            Some(row) => row,
            None => return Ok(BusinessSnapshot::default()),
        };
        let payload: String = row
            .get(0)
            .map_err(|err| RepositoryError::Serialization(err.to_string()))?;
        let value: Value =
            serde_json::from_str(&payload).map_err(|err| RepositoryError::Serialization(err.to_string()))?;
        serde_json::from_value(value).map_err(|err| RepositoryError::Serialization(err.to_string()))
    }

    fn save_snapshot(&self, snapshot: &BusinessSnapshot) -> Result<(), RepositoryError> {
        let payload =
            serde_json::to_string(snapshot).map_err(|err| RepositoryError::Serialization(err.to_string()))?;
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO business_snapshot (id, snapshot, updated_at)
             VALUES (1, ?1, CURRENT_TIMESTAMP)
             ON CONFLICT(id) DO UPDATE
             SET snapshot = excluded.snapshot, updated_at = CURRENT_TIMESTAMP",
            params![payload],
        )
        .map_err(|err| RepositoryError::Store(err.to_string()))?;
        Ok(())
    }

    fn is_seeded(&self) -> Result<bool, RepositoryError> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT 1 FROM business_snapshot WHERE id = 1")
            .map_err(|err| RepositoryError::Store(err.to_string()))?;
        let mut rows = stmt
            .query([])
            .map_err(|err| RepositoryError::Store(err.to_string()))?;
        Ok(rows
            .next()
            .map_err(|err| RepositoryError::Store(err.to_string()))?
            .is_some())
    }
}
