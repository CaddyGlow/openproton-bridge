pub mod error;
mod query;
mod schema;
pub mod store;
pub mod types;

pub use error::{ContactsStoreError, Result};
pub use store::ContactsStore;
pub use types::{ContactCardUpsert, ContactEmailUpsert, ContactUpsert, QueryPage, StoredContact};
