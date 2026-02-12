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

//! # Workspace
//!
//! This module provides the workspace abstraction for devcontainer projects.

use std::fs;
use std::path::PathBuf;

use crate::devcontainer::Devcontainer;

/// Represents a workspace containing a devcontainer configuration.
///
/// This structure holds the path to the project directory and
/// the parsed devcontainer configuration.
///
/// # Fields
///
/// * `path` - The path to the project directory
/// * `devcontainer` - The parsed devcontainer configuration
///
/// # Examples
///
/// ```no_run
/// use std::path::PathBuf;
/// use devcon::workspace::Workspace;
///
/// let workspace = Workspace::try_from(PathBuf::from("/path/to/project"))?;
/// # Ok::<(), devcon::error::Error>(())
/// ```
#[derive(Clone)]
pub struct Workspace {
    pub path: PathBuf,
    pub devcontainer: Devcontainer,
}

impl TryFrom<PathBuf> for Workspace {
    type Error = crate::error::Error;

    fn try_from(path: PathBuf) -> std::result::Result<Self, Self::Error> {
        let canonical_path = fs::canonicalize(&path)?;
        let devcontainer = Devcontainer::try_from(canonical_path.clone())?;

        Ok(Workspace {
            path: canonical_path,
            devcontainer,
        })
    }
}

impl Workspace {
    pub fn get_name(&self) -> String {
        if let Some(name) = self.devcontainer.name.as_ref() {
            return name.clone();
        }

        self.path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("unknown")
            .to_string()
    }

    pub fn get_sanitized_name(&self) -> String {
        let name = self.get_name();

        name.to_ascii_lowercase().replace(
            |c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_',
            "-",
        )
    }
}
