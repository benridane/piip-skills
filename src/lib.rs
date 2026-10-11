//! PIIP — PII Protection, as a fast local CLI.
//!
//! Rule-based detection and masking of personal data and secrets, with
//! Microsoft Presidio as an optional deeper backend.

pub mod config;
pub mod detector;
pub mod engine;
pub mod hook;
pub mod masker;
pub mod patterns;
pub mod presidio;
pub mod regex;
