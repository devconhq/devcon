// MIT License
//
// Copyright (c) 2025 DevCon Contributors
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

//! # Error Types
//!
//! This module defines the custom error types used throughout the DevCon application.
//! All errors are consolidated into a single `Error` enum for consistent error handling.

use std::io;
use std::path::PathBuf;
use thiserror::Error;

/// The main error type for DevCon operations.
///
/// This enum consolidates all possible errors that can occur during DevCon operations,
/// providing detailed context for debugging and user-friendly error messages.
#[derive(Error, Debug)]
pub enum Error {
    /// IO error occurred during file operations
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// JSON parsing or serialization error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// YAML parsing or serialization error
    #[error("YAML error: {0}")]
    Yaml(#[from] yaml_serde::Error),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Invalid path error
    #[error("Invalid path: {0}")]
    InvalidPath(PathBuf),

    /// Container runtime error
    #[error("Container runtime error: {0}")]
    Runtime(String),

    /// Container not found
    #[error("Container not found: {0}")]
    ContainerNotFound(String),

    /// Image not found
    #[error("Image not found: {0}")]
    ImageNotFound(String),

    /// Feature processing error
    #[error("Feature processing error: {0}")]
    Feature(String),

    /// Network/HTTP request error
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    /// Template rendering error
    #[error("Template error: {0}")]
    Template(#[from] minijinja::Error),

    /// OCI specification error
    #[error("OCI spec error: {0}")]
    OciSpec(#[from] oci_spec::OciSpecError),

    /// Devcontainer configuration error
    #[error("Devcontainer error: {0}")]
    Devcontainer(String),

    /// Workspace error
    #[error("Workspace error: {0}")]
    Workspace(String),

    /// Unknown or unsupported property
    #[error("Unknown property: {0}")]
    UnknownProperty(String),

    /// Invalid value for a property
    #[error("Invalid value for property '{property}': {message}")]
    InvalidValue { property: String, message: String },

    /// Missing required property
    #[error("Missing required property: {0}")]
    MissingProperty(String),

    /// Cache directory error
    #[error("Could not determine cache directory")]
    CacheDir,

    /// Feature not found
    #[error("Feature not found: {0}")]
    FeatureNotFound(String),

    /// No layers found in manifest
    #[error("No layers found in manifest for feature: {0}")]
    NoLayers(String),

    /// Token not found in authentication response
    #[error("Token not found in response for feature: {0}")]
    NoToken(String),

    /// Command execution failed
    #[error("Command execution failed: {0}")]
    CommandFailed(String),

    /// Prost encode/decode error
    #[error("Protocol buffer error: {0}")]
    Prost(#[from] prost::EncodeError),

    /// Indicatif template error
    #[error("Template rendering error: {0}")]
    IndicatifTemplate(#[from] indicatif::style::TemplateError),

    /// Generic error with custom message
    #[error("{0}")]
    Generic(String),
}

/// A specialized `Result` type for DevCon operations.
///
/// This type alias simplifies function signatures throughout the codebase
/// by defaulting to our custom `Error` type.
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Creates a new generic error with a custom message.
    ///
    /// # Examples
    ///
    /// ```
    /// use devcon::error::Error;
    ///
    /// let err = Error::new("Something went wrong");
    /// ```
    pub fn new(msg: impl Into<String>) -> Self {
        Error::Generic(msg.into())
    }

    /// Creates a new configuration error.
    ///
    /// # Examples
    ///
    /// ```
    /// use devcon::error::Error;
    ///
    /// let err = Error::config("Invalid configuration file");
    /// ```
    pub fn config(msg: impl Into<String>) -> Self {
        Error::Config(msg.into())
    }

    /// Creates a new runtime error.
    ///
    /// # Examples
    ///
    /// ```
    /// use devcon::error::Error;
    ///
    /// let err = Error::runtime("Docker daemon not running");
    /// ```
    pub fn runtime(msg: impl Into<String>) -> Self {
        Error::Runtime(msg.into())
    }

    /// Creates a new feature error.
    ///
    /// # Examples
    ///
    /// ```
    /// use devcon::error::Error;
    ///
    /// let err = Error::feature("Failed to download feature");
    /// ```
    pub fn feature(msg: impl Into<String>) -> Self {
        Error::Feature(msg.into())
    }

    /// Creates a new devcontainer error.
    ///
    /// # Examples
    ///
    /// ```
    /// use devcon::error::Error;
    ///
    /// let err = Error::devcontainer("Invalid devcontainer.json");
    /// ```
    pub fn devcontainer(msg: impl Into<String>) -> Self {
        Error::Devcontainer(msg.into())
    }

    /// Creates a new workspace error.
    ///
    /// # Examples
    ///
    /// ```
    /// use devcon::error::Error;
    ///
    /// let err = Error::workspace("Workspace not found");
    /// ```
    pub fn workspace(msg: impl Into<String>) -> Self {
        Error::Workspace(msg.into())
    }

    /// Creates a new unknown property error.
    ///
    /// # Examples
    ///
    /// ```
    /// use devcon::error::Error;
    ///
    /// let err = Error::unknown_property("invalidProp");
    /// ```
    pub fn unknown_property(property: impl Into<String>) -> Self {
        Error::UnknownProperty(property.into())
    }

    /// Creates a new invalid value error.
    ///
    /// # Examples
    ///
    /// ```
    /// use devcon::error::Error;
    ///
    /// let err = Error::invalid_value("port", "must be a number");
    /// ```
    pub fn invalid_value(property: impl Into<String>, message: impl Into<String>) -> Self {
        Error::InvalidValue {
            property: property.into(),
            message: message.into(),
        }
    }

    /// Creates a new invalid path error.
    ///
    /// # Examples
    ///
    /// ```
    /// use devcon::error::Error;
    /// use std::path::PathBuf;
    ///
    /// let err = Error::invalid_path(PathBuf::from("/invalid/path"));
    /// ```
    pub fn invalid_path(path: impl Into<PathBuf>) -> Self {
        Error::InvalidPath(path.into())
    }
}
