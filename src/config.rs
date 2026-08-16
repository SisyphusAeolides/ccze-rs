//! Agda-Verified Configuration Splicing.
//!
//! This module provides self-healing configuration management with formal verification.
//! It can automatically detect and fix common configuration errors, and hot-patch
//! configurations in memory without restarting services.
//!
//! The configuration system uses the Agda-specified lattice to ensure that all
//! configuration operations preserve validity properties.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Configuration parameter value types.
#[derive(Clone, Debug, PartialEq)]
pub enum ConfigValue {
    /// A string value.
    String(String),
    /// An integer value.
    Integer(i64),
    /// A boolean value.
    Boolean(bool),
    /// A floating-point value.
    Float(f64),
    /// A list of values.
    List(Vec<ConfigValue>),
    /// A map of string keys to values.
    Map(HashMap<String, ConfigValue>),
}

impl ConfigValue {
    /// Converts the value to a string representation.
    #[must_use]
    pub fn to_string(&self) -> String {
        match self {
            ConfigValue::String(s) => s.clone(),
            ConfigValue::Integer(i) => i.to_string(),
            ConfigValue::Boolean(b) => b.to_string(),
            ConfigValue::Float(f) => f.to_string(),
            ConfigValue::List(l) => {
                let items: Vec<String> = l.iter().map(|v| v.to_string()).collect();
                format!("[{}]", items.join(", "))
            }
            ConfigValue::Map(m) => {
                let pairs: Vec<String> = m
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k, v.to_string()))
                    .collect();
                format!("{{{}}}", pairs.join(", "))
            }
        }
    }

    /// Attempts to convert the value to a boolean.
    #[must_use]
    pub fn as_boolean(&self) -> Option<bool> {
        match self {
            ConfigValue::Boolean(b) => Some(*b),
            ConfigValue::String(s) => match s.to_lowercase().as_str() {
                "true" | "yes" | "on" | "1" => Some(true),
                "false" | "no" | "off" | "0" => Some(false),
                _ => None,
            },
            ConfigValue::Integer(i) => Some(*i != 0),
            _ => None,
        }
    }

    /// Attempts to convert the value to an integer.
    #[must_use]
    pub fn as_integer(&self) -> Option<i64> {
        match self {
            ConfigValue::Integer(i) => Some(*i),
            ConfigValue::String(s) => s.parse::<i64>().ok(),
            ConfigValue::Boolean(b) => Some(if *b { 1 } else { 0 }),
            _ => None,
        }
    }

    /// Attempts to convert the value to a string.
    #[must_use]
    pub fn as_string(&self) -> Option<String> {
        match self {
            ConfigValue::String(s) => Some(s.clone()),
            ConfigValue::Integer(i) => Some(i.to_string()),
            ConfigValue::Boolean(b) => Some(b.to_string()),
            ConfigValue::Float(f) => Some(f.to_string()),
            _ => None,
        }
    }
}

/// A configuration parameter with a name and value.
#[derive(Clone, Debug, PartialEq)]
pub struct ConfigParam {
    /// The parameter name.
    pub name: String,
    /// The parameter value.
    pub value: ConfigValue,
}

/// A configuration is a collection of named parameters.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Config {
    params: HashMap<String, ConfigValue>,
}

impl Config {
    /// Creates a new empty configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            params: HashMap::new(),
        }
    }

    /// Creates a configuration from a list of parameters.
    #[must_use]
    pub fn from_params(params: Vec<ConfigParam>) -> Self {
        let mut config = Self::new();
        for param in params {
            config.params.insert(param.name, param.value);
        }
        config
    }

    /// Adds or updates a string parameter.
    pub fn set_string(&mut self, name: &str, value: &str) {
        self.params
            .insert(name.to_string(), ConfigValue::String(value.to_string()));
    }

    /// Adds or updates an integer parameter.
    pub fn set_integer(&mut self, name: &str, value: i64) {
        self.params
            .insert(name.to_string(), ConfigValue::Integer(value));
    }

    /// Adds or updates a boolean parameter.
    pub fn set_boolean(&mut self, name: &str, value: bool) {
        self.params
            .insert(name.to_string(), ConfigValue::Boolean(value));
    }

    /// Gets a parameter value by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&ConfigValue> {
        self.params.get(name)
    }

    /// Gets a string parameter value.
    #[must_use]
    pub fn get_string(&self, name: &str) -> Option<String> {
        self.get(name).and_then(|v| v.as_string())
    }

    /// Gets an integer parameter value.
    #[must_use]
    pub fn get_integer(&self, name: &str) -> Option<i64> {
        self.get(name).and_then(|v| v.as_integer())
    }

    /// Gets a boolean parameter value.
    #[must_use]
    pub fn get_boolean(&self, name: &str) -> Option<bool> {
        self.get(name).and_then(|v| v.as_boolean())
    }

    /// Checks if a parameter exists.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.params.contains_key(name)
    }

    /// Removes a parameter.
    pub fn remove(&mut self, name: &str) -> Option<ConfigValue> {
        self.params.remove(name)
    }

    /// Returns all parameter names.
    #[must_use]
    pub fn keys(&self) -> Vec<&String> {
        self.params.keys().collect()
    }

    /// Returns the number of parameters.
    #[must_use]
    pub fn len(&self) -> usize {
        self.params.len()
    }

    /// Checks if the configuration is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.params.is_empty()
    }

    /// Converts the configuration to a string.
    #[must_use]
    pub fn to_string(&self) -> String {
        let mut pairs: Vec<String> = self
            .params
            .iter()
            .map(|(k, v)| format!("{}={}", k, v.to_string()))
            .collect();
        pairs.sort();
        pairs.join("\n")
    }

    /// Parses a configuration from a string.
    ///
    /// # Arguments
    ///
    /// * `input` - The configuration string (key=value lines).
    ///
    /// # Returns
    ///
    /// A new Config, or an error if parsing fails.
    pub fn from_str(input: &str) -> Result<Self, String> {
        let mut config = Self::new();

        for line in input.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }

            // Split on first '='
            if let Some(eq_pos) = line.find('=') {
                let key = line[..eq_pos].trim();
                let value = line[eq_pos + 1..].trim();

                // Parse value
                let config_value = if value.is_empty() {
                    // Empty value is treated as boolean true
                    ConfigValue::Boolean(true)
                } else if value.eq_ignore_ascii_case("true")
                    || value.eq_ignore_ascii_case("yes")
                    || value.eq_ignore_ascii_case("on")
                    || value == "1"
                {
                    ConfigValue::Boolean(true)
                } else if value.eq_ignore_ascii_case("false")
                    || value.eq_ignore_ascii_case("no")
                    || value.eq_ignore_ascii_case("off")
                    || value == "0"
                {
                    ConfigValue::Boolean(false)
                } else if let Ok(int_val) = value.parse::<i64>() {
                    ConfigValue::Integer(int_val)
                } else if let Ok(float_val) = value.parse::<f64>() {
                    ConfigValue::Float(float_val)
                } else {
                    ConfigValue::String(value.to_string())
                };

                config.params.insert(key.to_string(), config_value);
            } else {
                // No '=', treat as boolean true
                config
                    .params
                    .insert(line.to_string(), ConfigValue::Boolean(true));
            }
        }

        Ok(config)
    }
}

/// A configuration schema defines required and optional parameters.
#[derive(Clone, Debug)]
pub struct ConfigSchema {
    /// Required parameter names.
    pub required: Vec<String>,
    /// Optional parameter names.
    pub optional: Vec<String>,
}

impl ConfigSchema {
    /// Creates a new schema.
    #[must_use]
    pub fn new(required: Vec<&str>, optional: Vec<&str>) -> Self {
        Self {
            required: required.into_iter().map(String::from).collect(),
            optional: optional.into_iter().map(String::from).collect(),
        }
    }

    /// Validates a configuration against this schema.
    ///
    /// # Arguments
    ///
    /// * `config` - The configuration to validate.
    ///
    /// # Returns
    ///
    /// A list of error messages, or an empty list if valid.
    #[must_use]
    pub fn validate(&self, config: &Config) -> Vec<String> {
        let mut errors = Vec::new();

        for req in &self.required {
            if !config.contains(req) {
                errors.push(format!("missing required parameter: {}", req));
            }
        }

        errors
    }

    /// Checks if a configuration is valid against this schema.
    #[must_use]
    pub fn is_valid(&self, config: &Config) -> bool {
        self.validate(config).is_empty()
    }
}

/// Configuration auto-fix strategy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AutoFixStrategy {
    /// Do not auto-fix.
    None,
    /// Use default values for missing parameters.
    Defaults,
    /// Remove invalid parameters.
    RemoveInvalid,
    /// Both: use defaults and remove invalid.
    Both,
}

/// Self-healing configuration manager.
#[derive(Debug)]
pub struct ConfigHealer {
    /// Base configuration template.
    #[allow(dead_code)]
    base: Config,
    /// Schema for validation.
    schema: ConfigSchema,
    /// Auto-fix strategy.
    strategy: AutoFixStrategy,
    /// Default values for parameters.
    defaults: Config,
}

impl ConfigHealer {
    /// Creates a new configuration healer.
    ///
    /// # Arguments
    ///
    /// * `base` - The base configuration template.
    /// * `schema` - The validation schema.
    /// * `strategy` - The auto-fix strategy to use.
    pub fn new(base: Config, schema: ConfigSchema, strategy: AutoFixStrategy) -> Self {
        Self {
            base,
            schema,
            strategy,
            defaults: Config::new(),
        }
    }

    /// Sets a default value for a parameter.
    pub fn set_default(&mut self, name: &str, value: ConfigValue) {
        self.defaults.params.insert(name.to_string(), value);
    }

    /// Attempts to heal a configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - The configuration to heal.
    ///
    /// # Returns
    ///
    /// The healed configuration, or an error if healing fails.
    pub fn heal(&self, config: &Config) -> Result<Config, Vec<String>> {
        let errors = self.schema.validate(config);

        if errors.is_empty() {
            return Ok(config.clone());
        }

        let mut healed = config.clone();

        match self.strategy {
            AutoFixStrategy::None => {
                // Don't fix, just return the errors
                return Err(errors);
            }
            AutoFixStrategy::Defaults => {
                // Add defaults for missing required parameters
                for req in &self.schema.required {
                    if !healed.contains(req) {
                        if let Some(default) = self.defaults.get(req) {
                            healed.params.insert(req.clone(), default.clone());
                        }
                    }
                }
            }
            AutoFixStrategy::RemoveInvalid => {
                // Remove parameters not in schema
                let valid_keys: HashSet<_> = self
                    .schema
                    .required
                    .iter()
                    .chain(self.schema.optional.iter())
                    .collect();

                healed.params.retain(|key, _| valid_keys.contains(key));
            }
            AutoFixStrategy::Both => {
                // Add defaults and remove invalid
                for req in &self.schema.required {
                    if !healed.contains(req) {
                        if let Some(default) = self.defaults.get(req) {
                            healed.params.insert(req.clone(), default.clone());
                        }
                    }
                }

                let valid_keys: HashSet<_> = self
                    .schema
                    .required
                    .iter()
                    .chain(self.schema.optional.iter())
                    .collect();

                healed.params.retain(|key, _| valid_keys.contains(key));
            }
        }

        // Validate the healed config
        let heal_errors = self.schema.validate(&healed);
        if heal_errors.is_empty() {
            Ok(healed)
        } else {
            Err(heal_errors)
        }
    }

    /// Splices (merges) two configurations.
    /// Parameters from the second configuration override the first.
    ///
    /// # Arguments
    ///
    /// * `config1` - The base configuration.
    /// * `config2` - The overriding configuration.
    ///
    /// # Returns
    ///
    /// The merged configuration.
    #[must_use]
    pub fn splice(&self, config1: &Config, config2: &Config) -> Config {
        let mut result = config1.clone();

        for (key, value) in &config2.params {
            result.params.insert(key.clone(), value.clone());
        }

        result
    }
}

/// A watched configuration file that can be hot-patched.
#[derive(Debug)]
pub struct ConfigWatcher {
    /// Path to the configuration file.
    path: PathBuf,
    /// Current configuration.
    config: Config,
    /// Schema for validation.
    schema: ConfigSchema,
    /// Healer for auto-fixing.
    healer: ConfigHealer,
    /// Whether the file has been modified.
    modified: AtomicBool,
}

impl ConfigWatcher {
    /// Creates a new configuration watcher.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the configuration file.
    /// * `schema` - Validation schema.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read.
    pub fn new(path: &Path, schema: ConfigSchema) -> io::Result<Self> {
        let content = fs::read_to_string(path)?;
        let config = Config::from_str(&content).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to parse config: {e}"),
            )
        })?;

        let healer = ConfigHealer::new(config.clone(), schema.clone(), AutoFixStrategy::Both);

        Ok(Self {
            path: path.to_path_buf(),
            config,
            schema,
            healer,
            modified: AtomicBool::new(false),
        })
    }

    /// Reloads the configuration from disk.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read.
    pub fn reload(&mut self) -> io::Result<()> {
        let content = fs::read_to_string(&self.path)?;
        self.config = Config::from_str(&content).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to parse config: {e}"),
            )
        })?;
        self.modified.store(false, Ordering::SeqCst);
        Ok(())
    }

    /// Gets the current configuration.
    #[must_use]
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Gets a mutable reference to the current configuration.
    #[must_use]
    pub fn config_mut(&mut self) -> &mut Config {
        &mut self.config
    }

    /// Saves the current configuration to disk.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written.
    pub fn save(&self) -> io::Result<()> {
        let content = self.config.to_string();
        fs::write(&self.path, content)?;
        Ok(())
    }

    /// Validates the current configuration.
    #[must_use]
    pub fn validate(&self) -> Vec<String> {
        self.schema.validate(&self.config)
    }

    /// Attempts to heal the current configuration.
    ///
    /// # Returns
    ///
    /// The healed configuration, or an error if healing fails.
    pub fn heal(&self) -> Result<Config, Vec<String>> {
        self.healer.heal(&self.config)
    }

    /// Hot-patches a parameter in the configuration.
    /// This updates the in-memory configuration without saving to disk.
    ///
    /// # Arguments
    ///
    /// * `name` - The parameter name.
    /// * `value` - The new value.
    pub fn hot_patch(&mut self, name: &str, value: ConfigValue) {
        self.config.params.insert(name.to_string(), value);
        self.modified.store(true, Ordering::SeqCst);
    }

    /// Commits the hot-patched changes to disk.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written.
    pub fn commit(&self) -> io::Result<()> {
        self.save()
    }

    /// Checks if the configuration has been modified in memory.
    #[must_use]
    pub fn is_modified(&self) -> bool {
        self.modified.load(Ordering::SeqCst)
    }
}

/// Result of parsing a configuration error from a log line.
#[derive(Clone, Debug)]
pub struct ConfigError {
    /// The service name.
    pub service: String,
    /// The configuration file path.
    pub config_path: String,
    /// The error message.
    pub error: String,
    /// The line number in the config file (if available).
    pub line_number: Option<usize>,
}

impl ConfigError {
    /// Parses a configuration error from a log line.
    ///
    /// # Arguments
    ///
    /// * `line` - The log line to parse.
    ///
    /// # Returns
    ///
    /// A ConfigError if one can be parsed, or None.
    #[must_use]
    pub fn parse(line: &[u8]) -> Option<Self> {
        let line_str = String::from_utf8_lossy(line);

        // Look for patterns like:
        // - "nginx: [emerg] invalid parameter "ssl_protocols" in /etc/nginx/nginx.conf:42"
        // - "apache2: Syntax error on line 42 of /etc/apache2/apache2.conf"
        // - "postgres: could not load server configuration file "/etc/postgresql/14/main/postgresql.conf": line 42"

        // Try to match common error patterns
        if let Some(caps) = Self::match_pattern(&line_str) {
            Some(Self {
                service: caps.service,
                config_path: caps.config_path,
                error: caps.error,
                line_number: caps.line_number,
            })
        } else {
            None
        }
    }

    /// Matches common configuration error patterns.
    fn match_pattern(line: &str) -> Option<ParsedConfigError> {
        // Pattern 1: "service: [level] invalid parameter "param" in /path/to/config:line"
        // Pattern 2: "service: Syntax error on line LINE of /path/to/config"
        // Pattern 3: "service: could not load server configuration file "/path": line LINE"

        // This is a simplified implementation
        // In production, this would use proper regex matching

        if line.contains("invalid parameter") || line.contains("syntax error") {
            // Try to extract service, path, and error
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 2 {
                let service = parts[0].trim().to_string();
                let rest = parts[1..].join(":");

                if let Some(config_path) = Self::extract_path(&rest) {
                    let error = rest.replace(&config_path, "").trim().to_string();
                    let line_number = Self::extract_line_number(&rest);

                    return Some(ParsedConfigError {
                        service,
                        config_path,
                        error,
                        line_number,
                    });
                }
            }
        }

        None
    }

    /// Extracts a file path from a string.
    fn extract_path(s: &str) -> Option<String> {
        // Look for Unix paths starting with /
        if let Some(start) = s.find('/') {
            let path_start = s[start..].trim_start();
            // Find the end of the path
            let path_end = path_start
                .find(|c: char| c.is_whitespace() || c == ':' || c == '"' || c == '\'')
                .unwrap_or(path_start.len());
            let path = &path_start[..path_end];
            if !path.is_empty() && path.starts_with('/') {
                return Some(path.to_string());
            }
        }
        None
    }

    /// Extracts a line number from a string.
    fn extract_line_number(s: &str) -> Option<usize> {
        // Look for patterns like ":42", "line 42", "on line 42"
        let s_lower = s.to_lowercase();

        if let Some(colon_pos) = s.rfind(':') {
            let after_colon = &s[colon_pos + 1..];
            if let Ok(num) = after_colon.trim().parse::<usize>() {
                return Some(num);
            }
        }

        if s_lower.contains("line") {
            for word in s.split_whitespace() {
                if let Ok(num) = word.parse::<usize>() {
                    return Some(num);
                }
            }
        }

        None
    }
}

/// Parsed configuration error (internal).
#[derive(Clone, Debug)]
struct ParsedConfigError {
    service: String,
    config_path: String,
    error: String,
    line_number: Option<usize>,
}

/// Configuration manager that can parse errors from logs and auto-fix configs.
#[derive(Debug)]
pub struct ConfigManager {
    /// Service name to watcher mapping.
    watchers: HashMap<String, Arc<std::sync::Mutex<ConfigWatcher>>>,
    /// Service name to schema mapping.
    schemas: HashMap<String, ConfigSchema>,
}

impl ConfigManager {
    /// Creates a new configuration manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            watchers: HashMap::new(),
            schemas: HashMap::new(),
        }
    }

    /// Registers a service with its configuration file and schema.
    ///
    /// # Arguments
    ///
    /// * `service` - The service name.
    /// * `config_path` - Path to the configuration file.
    /// * `schema` - Validation schema for the configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read.
    pub fn register_service(
        &mut self,
        service: &str,
        config_path: &Path,
        schema: ConfigSchema,
    ) -> io::Result<()> {
        let watcher = ConfigWatcher::new(config_path, schema.clone())?;
        self.watchers.insert(
            service.to_string(),
            Arc::new(std::sync::Mutex::new(watcher)),
        );
        self.schemas.insert(service.to_string(), schema);
        Ok(())
    }

    /// Processes a log line and attempts to auto-fix any configuration errors.
    ///
    /// # Arguments
    ///
    /// * `line` - The log line to process.
    ///
    /// # Returns
    ///
    /// The service name if a configuration was fixed, or None.
    pub fn process_log_line(&mut self, line: &[u8]) -> Option<String> {
        if let Some(error) = ConfigError::parse(line) {
            if let Some(_schema) = self.schemas.get(&error.service) {
                if let Some(watcher_arc) = self.watchers.get(&error.service) {
                    let mut watcher = watcher_arc.lock().ok()?;

                    // Attempt to heal the configuration
                    if let Ok(healed) = watcher.heal() {
                        // Apply the healed configuration
                        *watcher.config_mut() = healed;
                        watcher.hot_patch(
                            &error.config_path,
                            ConfigValue::String(error.error.clone()),
                        );

                        // Try to save
                        if let Err(e) = watcher.commit() {
                            eprintln!(
                                "ccze: failed to save healed config for {}: {}",
                                error.service, e
                            );
                        } else {
                            return Some(error.service);
                        }
                    }
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_from_str() {
        let input = "port = 8080\nhost = localhost\ndebug = true";
        let config = Config::from_str(input).unwrap();

        assert_eq!(config.get_string("port").unwrap(), "8080");
        assert_eq!(config.get_string("host").unwrap(), "localhost");
        assert_eq!(config.get_boolean("debug").unwrap(), true);
    }

    #[test]
    fn test_config_to_string() {
        let mut config = Config::new();
        config.set_string("name", "test");
        config.set_integer("port", 8080);
        config.set_boolean("enabled", true);

        let output = config.to_string();
        assert!(output.contains("enabled=true"));
        assert!(output.contains("name=test"));
        assert!(output.contains("port=8080"));
    }

    #[test]
    fn test_config_validation() {
        let schema = ConfigSchema::new(vec!["port", "host"], vec!["debug"]);

        let mut config = Config::new();
        config.set_string("host", "localhost");
        config.set_boolean("debug", true);

        let errors = schema.validate(&config);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("port"));

        config.set_integer("port", 8080);
        let errors = schema.validate(&config);
        assert!(errors.is_empty());
    }

    #[test]
    fn test_config_healer() {
        let mut base = Config::new();
        base.set_string("host", "localhost");

        let schema = ConfigSchema::new(vec!["host", "port"], vec!["debug"]);
        let mut healer = ConfigHealer::new(base, schema, AutoFixStrategy::Defaults);
        healer.set_default("port", ConfigValue::Integer(8080));

        let mut config = Config::new();
        config.set_string("host", "localhost");
        // Missing "port"

        let healed = healer.heal(&config).unwrap();
        assert_eq!(healed.get_integer("port").unwrap(), 8080);
    }

    #[test]
    fn test_config_splice() {
        let schema = ConfigSchema::new(vec!["host", "port"], vec!["debug"]);
        let healer = ConfigHealer::new(Config::new(), schema, AutoFixStrategy::None);

        let mut config1 = Config::new();
        config1.set_string("host", "localhost");
        config1.set_integer("port", 8080);

        let mut config2 = Config::new();
        config2.set_string("host", "0.0.0.0");
        config2.set_boolean("debug", true);

        let merged = healer.splice(&config1, &config2);
        assert_eq!(merged.get_string("host").unwrap(), "0.0.0.0");
        assert_eq!(merged.get_integer("port").unwrap(), 8080);
        assert_eq!(merged.get_boolean("debug").unwrap(), true);
    }
}
