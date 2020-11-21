use anyhow::Result;
use serde::Deserialize;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

// Encapsulates various configuration parameters
#[derive(Clone, Deserialize, Default, Debug)]
#[serde(default)]
pub struct Config {
    pub server: Server,
}

#[derive(Clone, Deserialize, Default, Debug)]
#[serde(default)]
pub struct Server {
    pub proxy: Option<String>,
    pub target: String,
}

impl Config {
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Config> {
        let mut fd = File::open(path)?;
        let mut toml = String::new();
        fd.read_to_string(&mut toml)?;
        Self::from_string(&toml)
    }

    pub fn from_string(toml: &str) -> Result<Config> {
        let c: Config = toml::from_str(toml)?;
        Ok(c)
    }
}
