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

use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Devcontainer error: {0}")]
    Devcontainer(String),

    #[error("Feature processing error: {0}")]
    Feature(String),

    #[error("Invalid path: {0}")]
    InvalidPath(PathBuf),

    #[error("Either 'image' or 'build.dockerfile' must be specified in devcontainer.json")]
    MissingImageOrBuild,

    #[error(
        "Cannot specify both 'image' and 'build' in devcontainer.json - they are mutually exclusive"
    )]
    MutuallyExclusiveImageBuild,

    #[error("Dockerfile not found at path: {0}")]
    DockerfileNotFound(PathBuf),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn feature(msg: impl Into<String>) -> Self {
        Error::Feature(msg.into())
    }

    pub fn devcontainer(msg: impl Into<String>) -> Self {
        Error::Devcontainer(msg.into())
    }

    pub fn invalid_path(path: impl Into<PathBuf>) -> Self {
        Error::InvalidPath(path.into())
    }
}
