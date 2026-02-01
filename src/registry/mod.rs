/*!
Registry module for Portero.

This module groups the data structures and logic related to backend registration
and routing. Public types are re-exported for convenient access.
*/

pub mod models;

pub use models::{Backend, Registry};
