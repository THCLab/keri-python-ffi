use std::io;

use base64::DecodeError;
use keri::error::Error as KeriError;
use rustbreak::RustbreakError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    DynError(#[from] Box<dyn std::error::Error>),
    #[error(transparent)]
    KeriError(#[from] KeriError),
    #[error(transparent)]
    StringFromUtf8Error(#[from] std::string::FromUtf8Error),
    #[error(transparent)]
    Decode64Error(#[from] DecodeError),
    #[error(transparent)]
    AddressProviderError(#[from] RustbreakError),
    #[error(transparent)]
    CommunicationError(#[from] io::Error),
    #[error("{0}")]
    Generic(String),
}
