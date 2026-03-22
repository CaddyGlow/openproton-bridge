#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactUpsert {
    pub id: String,
    pub uid: String,
    pub name: String,
    pub size: i64,
    pub create_time: i64,
    pub modify_time: i64,
    pub raw_json: String,
    pub cards: Vec<ContactCardUpsert>,
    pub emails: Vec<ContactEmailUpsert>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactCardUpsert {
    pub card_type: i64,
    pub data: String,
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactEmailUpsert {
    pub id: String,
    pub contact_id: String,
    pub email: String,
    pub name: String,
    pub kind_json: String,
    pub defaults: Option<i64>,
    pub order: Option<i64>,
    pub label_ids_json: String,
    pub last_used_time: Option<i64>,
    pub raw_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredContact {
    pub id: String,
    pub uid: String,
    pub name: String,
    pub size: i64,
    pub create_time: i64,
    pub modify_time: i64,
    pub deleted: bool,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryPage {
    pub limit: usize,
    pub offset: usize,
}

impl Default for QueryPage {
    fn default() -> Self {
        Self {
            limit: DEFAULT_PAGE_LIMIT,
            offset: 0,
        }
    }
}

pub const DEFAULT_PAGE_LIMIT: usize = 100;
pub const MAX_PAGE_LIMIT: usize = 500;
