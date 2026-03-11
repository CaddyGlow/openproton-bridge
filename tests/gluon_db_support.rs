#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::Path;

use rusqlite::OptionalExtension;
use serde_json::{json, Map, Value};

const META_TABLE: &str = "openproton_account_meta";
const MAILBOX_TABLE: &str = "openproton_mailboxes";
const MESSAGE_TABLE: &str = "openproton_messages";
const LABEL_TABLE: &str = "openproton_message_labels";
const ADDRESS_TABLE: &str = "openproton_message_addresses";
const FLAG_TABLE: &str = "openproton_message_flags";
const NEXT_BLOB_ID_KEY: &str = "next_blob_id";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum AddressFieldKind {
    To,
    Cc,
    Bcc,
    ReplyTo,
}

impl AddressFieldKind {
    fn as_sql(self) -> &'static str {
        match self {
            Self::To => "to",
            Self::Cc => "cc",
            Self::Bcc => "bcc",
            Self::ReplyTo => "reply_to",
        }
    }

    fn from_sql(value: &str) -> Option<Self> {
        match value {
            "to" => Some(Self::To),
            "cc" => Some(Self::Cc),
            "bcc" => Some(Self::Bcc),
            "reply_to" => Some(Self::ReplyTo),
            _ => None,
        }
    }
}

fn schema() -> String {
    format!(
        "CREATE TABLE IF NOT EXISTS {META_TABLE} (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS {MAILBOX_TABLE} (
            mailbox_name TEXT PRIMARY KEY,
            uid_validity INTEGER NOT NULL,
            next_uid INTEGER NOT NULL,
            mod_seq INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS {MESSAGE_TABLE} (
            mailbox_name TEXT NOT NULL,
            uid INTEGER NOT NULL,
            proton_id TEXT,
            blob_name TEXT,
            address_id TEXT,
            external_id TEXT,
            subject TEXT,
            sender_name TEXT,
            sender_address TEXT,
            flags INTEGER,
            time INTEGER,
            size INTEGER,
            unread INTEGER,
            is_replied INTEGER,
            is_replied_all INTEGER,
            is_forwarded INTEGER,
            num_attachments INTEGER,
            PRIMARY KEY (mailbox_name, uid)
        );
        CREATE UNIQUE INDEX IF NOT EXISTS openproton_messages_mailbox_proton_idx
            ON {MESSAGE_TABLE}(mailbox_name, proton_id)
            WHERE proton_id IS NOT NULL;
        CREATE TABLE IF NOT EXISTS {LABEL_TABLE} (
            mailbox_name TEXT NOT NULL,
            uid INTEGER NOT NULL,
            ordinal INTEGER NOT NULL,
            label_id TEXT NOT NULL,
            PRIMARY KEY (mailbox_name, uid, ordinal)
        );
        CREATE TABLE IF NOT EXISTS {ADDRESS_TABLE} (
            mailbox_name TEXT NOT NULL,
            uid INTEGER NOT NULL,
            field_kind TEXT NOT NULL,
            ordinal INTEGER NOT NULL,
            name TEXT NOT NULL,
            address TEXT NOT NULL,
            PRIMARY KEY (mailbox_name, uid, field_kind, ordinal)
        );
        CREATE TABLE IF NOT EXISTS {FLAG_TABLE} (
            mailbox_name TEXT NOT NULL,
            uid INTEGER NOT NULL,
            ordinal INTEGER NOT NULL,
            flag TEXT NOT NULL,
            PRIMARY KEY (mailbox_name, uid, ordinal)
        );"
    )
}

fn reset_schema(conn: &rusqlite::Connection) {
    conn.execute_batch(&schema())
        .expect("create relational gluon schema");
    conn.execute(&format!("DELETE FROM {META_TABLE}"), [])
        .expect("clear meta table");
    conn.execute(&format!("DELETE FROM {MAILBOX_TABLE}"), [])
        .expect("clear mailbox table");
    conn.execute(&format!("DELETE FROM {MESSAGE_TABLE}"), [])
        .expect("clear message table");
    conn.execute(&format!("DELETE FROM {LABEL_TABLE}"), [])
        .expect("clear label table");
    conn.execute(&format!("DELETE FROM {ADDRESS_TABLE}"), [])
        .expect("clear address table");
    conn.execute(&format!("DELETE FROM {FLAG_TABLE}"), [])
        .expect("clear flag table");
}

pub fn write_legacy_index_payload(db_path: &Path, index_payload: &Value) {
    if let Some(parent) = db_path.parent() {
        fs::create_dir_all(parent).expect("create parent dir for relational db");
    }

    let conn = rusqlite::Connection::open(db_path)
        .unwrap_or_else(|err| panic!("open sqlite db {} failed: {err}", db_path.display()));
    reset_schema(&conn);

    let next_blob_id = index_payload
        .get("next_blob_id")
        .and_then(Value::as_u64)
        .unwrap_or(1)
        .max(1);
    conn.execute(
        &format!("INSERT INTO {META_TABLE} (key, value) VALUES (?1, ?2)"),
        rusqlite::params![NEXT_BLOB_ID_KEY, next_blob_id.to_string()],
    )
    .expect("insert next_blob_id");

    let Some(mailboxes) = index_payload.get("mailboxes").and_then(Value::as_object) else {
        return;
    };

    for (mailbox_name, mailbox_value) in mailboxes {
        let mailbox = mailbox_value
            .as_object()
            .unwrap_or_else(|| panic!("mailbox {mailbox_name} must be an object"));
        conn.execute(
            &format!(
                "INSERT INTO {MAILBOX_TABLE} (mailbox_name, uid_validity, next_uid, mod_seq)
                 VALUES (?1, ?2, ?3, ?4)"
            ),
            rusqlite::params![
                mailbox_name,
                mailbox
                    .get("uid_validity")
                    .and_then(Value::as_u64)
                    .unwrap_or(1) as u32,
                mailbox.get("next_uid").and_then(Value::as_u64).unwrap_or(1) as u32,
                mailbox.get("mod_seq").and_then(Value::as_u64).unwrap_or(0)
            ],
        )
        .expect("insert mailbox row");

        let proton_to_uid = mailbox
            .get("proton_to_uid")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let uid_to_proton = mailbox
            .get("uid_to_proton")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let metadata = mailbox
            .get("metadata")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let flags = mailbox
            .get("flags")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let uid_to_blob = mailbox
            .get("uid_to_blob")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();

        let mut all_uids = BTreeMap::<u32, ()>::new();
        for uid in mailbox
            .get("uid_order")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_u64)
            .map(|uid| uid as u32)
        {
            all_uids.insert(uid, ());
        }
        for uid in uid_to_proton
            .keys()
            .filter_map(|uid| uid.parse::<u32>().ok())
        {
            all_uids.insert(uid, ());
        }
        for uid in metadata.keys().filter_map(|uid| uid.parse::<u32>().ok()) {
            all_uids.insert(uid, ());
        }
        for uid in flags.keys().filter_map(|uid| uid.parse::<u32>().ok()) {
            all_uids.insert(uid, ());
        }
        for uid in uid_to_blob.keys().filter_map(|uid| uid.parse::<u32>().ok()) {
            all_uids.insert(uid, ());
        }

        for uid in all_uids.keys().copied() {
            let proton_id = uid_to_proton
                .get(uid.to_string().as_str())
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .or_else(|| {
                    proton_to_uid.iter().find_map(|(proton_id, value)| {
                        (value.as_u64() == Some(uid as u64)).then(|| proton_id.clone())
                    })
                });
            let blob_name = uid_to_blob
                .get(uid.to_string().as_str())
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            let meta = metadata
                .get(uid.to_string().as_str())
                .and_then(Value::as_object);

            conn.execute(
                &format!(
                    "INSERT INTO {MESSAGE_TABLE} (
                        mailbox_name, uid, proton_id, blob_name, address_id, external_id,
                        subject, sender_name, sender_address, flags, time, size, unread,
                        is_replied, is_replied_all, is_forwarded, num_attachments
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)"
                ),
                rusqlite::params![
                    mailbox_name,
                    uid,
                    proton_id.clone(),
                    blob_name,
                    meta.and_then(|meta| meta.get("AddressID")).and_then(Value::as_str),
                    meta.and_then(|meta| meta.get("ExternalID")).and_then(Value::as_str),
                    meta.and_then(|meta| meta.get("Subject")).and_then(Value::as_str),
                    meta.and_then(|meta| meta.get("Sender"))
                        .and_then(Value::as_object)
                        .and_then(|sender| sender.get("Name"))
                        .and_then(Value::as_str),
                    meta.and_then(|meta| meta.get("Sender"))
                        .and_then(Value::as_object)
                        .and_then(|sender| sender.get("Address"))
                        .and_then(Value::as_str),
                    meta.map(|meta| meta.get("Flags").and_then(Value::as_i64).unwrap_or(0)),
                    meta.and_then(|meta| meta.get("Time")).and_then(Value::as_i64),
                    meta.and_then(|meta| meta.get("Size")).and_then(Value::as_i64),
                    meta.and_then(|meta| meta.get("Unread")).and_then(Value::as_i64).map(|v| v as i32),
                    meta.map(|meta| meta.get("IsReplied").and_then(Value::as_i64).unwrap_or(0) as i32),
                    meta.map(|meta| meta.get("IsRepliedAll").and_then(Value::as_i64).unwrap_or(0) as i32),
                    meta.map(|meta| meta.get("IsForwarded").and_then(Value::as_i64).unwrap_or(0) as i32),
                    meta.and_then(|meta| meta.get("NumAttachments")).and_then(Value::as_i64).map(|v| v as i32),
                ],
            )
            .expect("insert message row");

            if let Some(meta) = meta {
                if let Some(label_ids) = meta.get("LabelIDs").and_then(Value::as_array) {
                    for (ordinal, label_id) in
                        label_ids.iter().filter_map(Value::as_str).enumerate()
                    {
                        conn.execute(
                            &format!(
                                "INSERT INTO {LABEL_TABLE} (mailbox_name, uid, ordinal, label_id)
                                 VALUES (?1, ?2, ?3, ?4)"
                            ),
                            rusqlite::params![mailbox_name, uid, ordinal as i64, label_id],
                        )
                        .expect("insert label row");
                    }
                }

                for (field_kind, field_name) in [
                    (AddressFieldKind::To, "ToList"),
                    (AddressFieldKind::Cc, "CCList"),
                    (AddressFieldKind::Bcc, "BCCList"),
                    (AddressFieldKind::ReplyTo, "ReplyTos"),
                ] {
                    let Some(entries) = meta.get(field_name).and_then(Value::as_array) else {
                        continue;
                    };
                    for (ordinal, entry) in entries.iter().filter_map(Value::as_object).enumerate()
                    {
                        conn.execute(
                            &format!(
                                "INSERT INTO {ADDRESS_TABLE} (
                                    mailbox_name, uid, field_kind, ordinal, name, address
                                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
                            ),
                            rusqlite::params![
                                mailbox_name,
                                uid,
                                field_kind.as_sql(),
                                ordinal as i64,
                                entry
                                    .get("Name")
                                    .and_then(Value::as_str)
                                    .unwrap_or_default(),
                                entry
                                    .get("Address")
                                    .and_then(Value::as_str)
                                    .unwrap_or_default(),
                            ],
                        )
                        .expect("insert address row");
                    }
                }
            }

            if let Some(flag_values) = flags
                .get(uid.to_string().as_str())
                .and_then(Value::as_array)
            {
                for (ordinal, flag) in flag_values.iter().filter_map(Value::as_str).enumerate() {
                    conn.execute(
                        &format!(
                            "INSERT INTO {FLAG_TABLE} (mailbox_name, uid, ordinal, flag)
                             VALUES (?1, ?2, ?3, ?4)"
                        ),
                        rusqlite::params![mailbox_name, uid, ordinal as i64, flag],
                    )
                    .expect("insert flag row");
                }
            }
        }
    }
}

pub fn build_db_bytes_from_legacy_index_payload(index_payload: &Value) -> Vec<u8> {
    let temp = tempfile::tempdir().expect("temp sqlite dir");
    let db_path = temp.path().join("index.db");
    write_legacy_index_payload(&db_path, index_payload);
    fs::read(db_path).expect("read sqlite db bytes")
}

pub fn read_legacy_index_payload(db_path: &Path) -> Value {
    let conn = rusqlite::Connection::open(db_path)
        .unwrap_or_else(|err| panic!("open sqlite db {} failed: {err}", db_path.display()));

    let next_blob_id = conn
        .query_row(
            &format!("SELECT value FROM {META_TABLE} WHERE key = ?1"),
            [NEXT_BLOB_ID_KEY],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .expect("query next_blob_id")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(1);

    let mailbox_rows = conn
        .prepare(&format!(
            "SELECT mailbox_name, uid_validity, next_uid, mod_seq
             FROM {MAILBOX_TABLE}
             ORDER BY mailbox_name"
        ))
        .expect("prepare mailbox query")
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, u32>(2)?,
                row.get::<_, u64>(3)?,
            ))
        })
        .expect("query mailboxes")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("collect mailboxes");

    let label_rows = conn
        .prepare(&format!(
            "SELECT mailbox_name, uid, label_id
             FROM {LABEL_TABLE}
             ORDER BY mailbox_name, uid, ordinal"
        ))
        .expect("prepare label query")
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .expect("query labels")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("collect labels");
    let mut labels_by_message: HashMap<(String, u32), Vec<String>> = HashMap::new();
    for (mailbox_name, uid, label_id) in label_rows {
        labels_by_message
            .entry((mailbox_name, uid))
            .or_default()
            .push(label_id);
    }

    let address_rows = conn
        .prepare(&format!(
            "SELECT mailbox_name, uid, field_kind, name, address
             FROM {ADDRESS_TABLE}
             ORDER BY mailbox_name, uid, field_kind, ordinal"
        ))
        .expect("prepare address query")
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .expect("query addresses")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("collect addresses");
    let mut addresses_by_message: HashMap<(String, u32, AddressFieldKind), Vec<Value>> =
        HashMap::new();
    for (mailbox_name, uid, field_kind, name, address) in address_rows {
        let Some(field_kind) = AddressFieldKind::from_sql(&field_kind) else {
            continue;
        };
        addresses_by_message
            .entry((mailbox_name, uid, field_kind))
            .or_default()
            .push(json!({
                "Name": name,
                "Address": address,
            }));
    }

    let flag_rows = conn
        .prepare(&format!(
            "SELECT mailbox_name, uid, flag
             FROM {FLAG_TABLE}
             ORDER BY mailbox_name, uid, ordinal"
        ))
        .expect("prepare flag query")
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .expect("query flags")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("collect flags");
    let mut flags_by_message: HashMap<(String, u32), Vec<String>> = HashMap::new();
    for (mailbox_name, uid, flag) in flag_rows {
        flags_by_message
            .entry((mailbox_name, uid))
            .or_default()
            .push(flag);
    }

    let message_rows = conn
        .prepare(&format!(
            "SELECT mailbox_name, uid, proton_id, blob_name, address_id, external_id,
                    subject, sender_name, sender_address, flags, time, size, unread,
                    is_replied, is_replied_all, is_forwarded, num_attachments
             FROM {MESSAGE_TABLE}
             ORDER BY mailbox_name, uid"
        ))
        .expect("prepare message query")
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, Option<i64>>(9)?,
                row.get::<_, Option<i64>>(10)?,
                row.get::<_, Option<i64>>(11)?,
                row.get::<_, Option<i32>>(12)?,
                row.get::<_, Option<i32>>(13)?,
                row.get::<_, Option<i32>>(14)?,
                row.get::<_, Option<i32>>(15)?,
                row.get::<_, Option<i32>>(16)?,
            ))
        })
        .expect("query messages")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("collect messages");

    let mut mailboxes_json = Map::new();
    for (mailbox_name, uid_validity, next_uid, mod_seq) in mailbox_rows {
        mailboxes_json.insert(
            mailbox_name.clone(),
            json!({
                "uid_validity": uid_validity,
                "next_uid": next_uid,
                "proton_to_uid": {},
                "uid_to_proton": {},
                "metadata": {},
                "flags": {},
                "uid_order": [],
                "mod_seq": mod_seq,
                "uid_to_blob": {},
            }),
        );
    }

    for (
        mailbox_name,
        uid,
        proton_id,
        blob_name,
        address_id,
        external_id,
        subject,
        sender_name,
        sender_address,
        flags,
        time,
        size,
        unread,
        is_replied,
        is_replied_all,
        is_forwarded,
        num_attachments,
    ) in message_rows
    {
        let mailbox = mailboxes_json
            .get_mut(&mailbox_name)
            .and_then(Value::as_object_mut)
            .expect("mailbox json object");
        mailbox
            .get_mut("uid_order")
            .and_then(Value::as_array_mut)
            .expect("uid_order array")
            .push(json!(uid));

        if let Some(proton_id) = proton_id.clone() {
            mailbox
                .get_mut("proton_to_uid")
                .and_then(Value::as_object_mut)
                .expect("proton_to_uid object")
                .insert(proton_id.clone(), json!(uid));
            mailbox
                .get_mut("uid_to_proton")
                .and_then(Value::as_object_mut)
                .expect("uid_to_proton object")
                .insert(uid.to_string(), json!(proton_id));
        }

        if let Some(blob_name) = blob_name {
            mailbox
                .get_mut("uid_to_blob")
                .and_then(Value::as_object_mut)
                .expect("uid_to_blob object")
                .insert(uid.to_string(), json!(blob_name));
        }

        if let (
            Some(proton_id),
            Some(address_id),
            Some(subject),
            Some(sender_name),
            Some(sender_address),
            Some(flags),
            Some(time),
            Some(size),
            Some(unread),
            Some(num_attachments),
        ) = (
            proton_id,
            address_id,
            subject,
            sender_name,
            sender_address,
            flags,
            time,
            size,
            unread,
            num_attachments,
        ) {
            let key = (mailbox_name.clone(), uid);
            mailbox
                .get_mut("metadata")
                .and_then(Value::as_object_mut)
                .expect("metadata object")
                .insert(
                    uid.to_string(),
                    json!({
                        "ID": proton_id,
                        "AddressID": address_id,
                        "LabelIDs": labels_by_message.remove(&key).unwrap_or_default(),
                        "ExternalID": external_id,
                        "Subject": subject,
                        "Sender": {
                            "Name": sender_name,
                            "Address": sender_address,
                        },
                        "ToList": addresses_by_message
                            .remove(&(mailbox_name.clone(), uid, AddressFieldKind::To))
                            .unwrap_or_default(),
                        "CCList": addresses_by_message
                            .remove(&(mailbox_name.clone(), uid, AddressFieldKind::Cc))
                            .unwrap_or_default(),
                        "BCCList": addresses_by_message
                            .remove(&(mailbox_name.clone(), uid, AddressFieldKind::Bcc))
                            .unwrap_or_default(),
                        "ReplyTos": addresses_by_message
                            .remove(&(mailbox_name.clone(), uid, AddressFieldKind::ReplyTo))
                            .unwrap_or_default(),
                        "Flags": flags,
                        "Time": time,
                        "Size": size,
                        "Unread": unread,
                        "IsReplied": is_replied.unwrap_or(0),
                        "IsRepliedAll": is_replied_all.unwrap_or(0),
                        "IsForwarded": is_forwarded.unwrap_or(0),
                        "NumAttachments": num_attachments,
                    }),
                );
        }

        if let Some(flag_list) = flags_by_message.remove(&(mailbox_name.clone(), uid)) {
            mailbox
                .get_mut("flags")
                .and_then(Value::as_object_mut)
                .expect("flags object")
                .insert(uid.to_string(), json!(flag_list));
        }
    }

    json!({
        "version": 1,
        "next_blob_id": next_blob_id,
        "mailboxes": Value::Object(mailboxes_json),
    })
}
