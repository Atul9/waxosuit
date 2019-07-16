// Copyright 2015-2018 Capital One Services, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::error::Error as StdError;
use std::fmt;

#[derive(Debug)]
pub struct Error(Box<ErrorKind>);

pub fn new(kind: ErrorKind) -> Error {
    Error(Box::new(kind))
}

#[derive(Debug)]
pub enum ErrorKind {
    NoSuchFunction(String),
    Encoding(prost::EncodeError),
    Decoding(prost::DecodeError),
    IO(std::io::Error),
    WasmRuntime(wasmer_runtime_core::error::RuntimeError),
    WasmMisc(wasmer_runtime_core::error::Error),
    WasmEntityResolution(wasmer_runtime_core::error::ResolveError),
    WascapViolation(String),
    HostCallFailure(Box<dyn StdError>),
    HttpClientFailure(reqwest::Error),
    Json(serde_json::error::Error),
    CapabilityProviderError(String),
    TokenValidationError(String),
}

impl Error {
    pub fn kind(&self) -> &ErrorKind {
        &self.0
    }

    pub fn into_kind(self) -> ErrorKind {
        *self.0
    }
}

impl StdError for Error {
    fn description(&self) -> &str {
        match *self.0 {
            ErrorKind::NoSuchFunction(_) => "No such function in Wasm module",
            ErrorKind::IO(_) => "I/O error",
            ErrorKind::Encoding(_) => "Encoding failure",
            ErrorKind::Decoding(_) => "Decoding failure",
            ErrorKind::WasmRuntime(_) => "WebAssembly runtime error",
            ErrorKind::WasmEntityResolution(_) => "WebAssembly entity resolution failure",
            ErrorKind::WasmMisc(_) => "WebAssembly failure",
            ErrorKind::WascapViolation(_) => "WASCAP contract violation",
            ErrorKind::HostCallFailure(_) => "Error occurred during host call",
            ErrorKind::HttpClientFailure(_) => "HTTP client error",
            ErrorKind::Json(_) => "JSON encoding/decoding failure",
            ErrorKind::CapabilityProviderError(_) => "Capability provider error",
            ErrorKind::TokenValidationError(_) => "Token validation error",
        }
    }

    fn cause(&self) -> Option<&StdError> {
        match *self.0 {
            ErrorKind::NoSuchFunction(_) => None,
            ErrorKind::IO(ref err) => Some(err),
            ErrorKind::Encoding(ref err) => Some(err),
            ErrorKind::Decoding(ref err) => Some(err),
            ErrorKind::WasmRuntime(ref err) => Some(err),
            ErrorKind::WasmEntityResolution(ref err) => Some(err),
            ErrorKind::WasmMisc(ref err) => Some(err),
            ErrorKind::WascapViolation(_) => None,
            ErrorKind::HostCallFailure(_) => None,
            ErrorKind::HttpClientFailure(ref err) => Some(err),
            ErrorKind::Json(ref err) => Some(err),
            ErrorKind::CapabilityProviderError(_) => None,
            ErrorKind::TokenValidationError(_) => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self.0 {
            ErrorKind::NoSuchFunction(ref fname) => {
                write!(f, "No such function in Wasm module: {}", fname)
            }
            ErrorKind::IO(ref err) => write!(f, "I/O error: {}", err),
            ErrorKind::Encoding(ref err) => write!(f, "Encoding failure: {}", err),
            ErrorKind::Decoding(ref err) => write!(f, "Decoding failure: {}", err),
            ErrorKind::WasmRuntime(ref err) => write!(f, "WebAssembly runtime error: {}", err),
            ErrorKind::WasmEntityResolution(ref err) => {
                write!(f, "WebAssembly entity resolution error: {}", err)
            }
            ErrorKind::WasmMisc(ref err) => write!(f, "WebAssembly error: {}", err),
            ErrorKind::WascapViolation(ref err) => write!(f, "WASCAP contract violation: {}", err),
            ErrorKind::HostCallFailure(ref err) => {
                write!(f, "Error occurred during host call: {}", err)

            }
            ErrorKind::HttpClientFailure(ref err) => write!(f, "HTTP client error: {}", err),
            ErrorKind::Json(ref err) => write!(f, "JSON error: {}", err),
            ErrorKind::CapabilityProviderError(ref desc) => write!(f, "Capability provider error: {}", desc),
            ErrorKind::TokenValidationError(ref reason) => write!(f, "Token validation error: {}", reason),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(source: std::io::Error) -> Error {
        Error(Box::new(ErrorKind::IO(source)))
    }
}

impl From<prost::EncodeError> for Error {
    fn from(source: prost::EncodeError) -> Error {
        Error(Box::new(ErrorKind::Encoding(source)))
    }
}

impl From<prost::DecodeError> for Error {
    fn from(source: prost::DecodeError) -> Error {
        Error(Box::new(ErrorKind::Decoding(source)))
    }
}

impl From<wasmer_runtime_core::error::RuntimeError> for Error {
    fn from(source: wasmer_runtime_core::error::RuntimeError) -> Error {
        Error(Box::new(ErrorKind::WasmRuntime(source)))
    }
}

impl From<wasmer_runtime_core::error::Error> for Error {
    fn from(source: wasmer_runtime_core::error::Error) -> Error {
        Error(Box::new(ErrorKind::WasmMisc(source)))
    }
}

impl From<wasmer_runtime_core::error::ResolveError> for Error {
    fn from(source: wasmer_runtime_core::error::ResolveError) -> Error {
        Error(Box::new(ErrorKind::WasmEntityResolution(source)))
    }
}

impl From<reqwest::Error> for Error {
    fn from(source: reqwest::Error) -> Error {
        Error(Box::new(ErrorKind::HttpClientFailure(source)))
    }
}

impl From<serde_json::error::Error> for Error {
    fn from(source: serde_json::error::Error) -> Error {
        Error(Box::new(ErrorKind::Json(source)))
    }
}
