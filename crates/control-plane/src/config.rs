use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::static_config::{StaticConfigItem, STATIC_CONFIG_TABLE};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SystemConfig {
    values: HashMap<String, String>,
}

impl SystemConfig {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(String::as_str)
    }

    pub fn get_string(&self, key: &str) -> String {
        self.get(key)
            .map(str::to_string)
            .or_else(|| default_value(key))
            .unwrap_or_default()
    }

    pub fn get_number(&self, key: &str) -> i64 {
        self.get(key)
            .and_then(|value| value.parse::<i64>().ok())
            .or_else(|| default_value(key).and_then(|value| value.parse::<i64>().ok()))
            .unwrap_or_default()
    }

    pub fn get_bool(&self, key: &str) -> bool {
        self.get(key)
            .and_then(parse_bool)
            .or_else(|| default_value(key).and_then(|value| parse_bool(&value)))
            .unwrap_or(false)
    }

    pub fn keys(&self) -> Vec<String> {
        self.values.keys().cloned().collect()
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("config parse error: {0}")]
    Parse(String),
    #[error("unknown config key: {0}")]
    UnknownKey(String),
    #[error("type mismatch for key {0}: expected {1}")]
    TypeMismatch(String, String),
}

pub struct SystemConfigLoader;

impl SystemConfigLoader {
    pub fn from_str(input: &str) -> Result<SystemConfig, ConfigError> {
        let value: toml::Value =
            toml::from_str(input).map_err(|err| ConfigError::Parse(err.to_string()))?;
        let mut values = HashMap::new();
        let mut errors = Vec::new();
        flatten_values(&mut values, String::new(), &value, &mut errors);
        if let Some(err) = errors.into_iter().next() {
            return Err(err);
        }
        Ok(SystemConfig { values })
    }
}

fn flatten_values(
    output: &mut HashMap<String, String>,
    prefix: String,
    value: &toml::Value,
    errors: &mut Vec<ConfigError>,
) {
    match value {
        toml::Value::Table(table) => {
            for (key, nested) in table {
                let new_prefix = if prefix.is_empty() {
                    key.to_string()
                } else {
                    format!("{prefix}.{key}")
                };
                flatten_values(output, new_prefix, nested, errors);
            }
        }
        toml::Value::String(value) => {
            insert_checked(output, &prefix, value.to_string(), "string", errors);
        }
        toml::Value::Integer(value) => {
            insert_checked(output, &prefix, value.to_string(), "number", errors);
        }
        toml::Value::Float(value) => {
            insert_checked(output, &prefix, value.to_string(), "number", errors);
        }
        toml::Value::Boolean(value) => {
            insert_checked(output, &prefix, value.to_string(), "boolean", errors);
        }
        _ => {
            errors.push(ConfigError::TypeMismatch(prefix, "string|number|boolean".to_string()));
        }
    }
}

fn insert_checked(
    output: &mut HashMap<String, String>,
    key: &str,
    value: String,
    expected_type: &str,
    errors: &mut Vec<ConfigError>,
) {
    let Some(item) = config_item(key) else {
        errors.push(ConfigError::UnknownKey(key.to_string()));
        return;
    };
    if item.value_type != expected_type {
        errors.push(ConfigError::TypeMismatch(key.to_string(), item.value_type.to_string()));
        return;
    }
    output.insert(key.to_string(), value);
}

fn config_item(key: &str) -> Option<&'static StaticConfigItem> {
    STATIC_CONFIG_TABLE.iter().find(|item| item.key == key)
}

fn default_value(key: &str) -> Option<String> {
    config_item(key).map(|item| item.default_value.to_string())
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.to_lowercase().as_str() {
        "true" | "1" | "yes" => Some(true),
        "false" | "0" | "no" => Some(false),
        _ => None,
    }
}
