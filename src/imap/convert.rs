use crate::api::types as api;
use gluon_rs_mail::{EmailAddress, MessageEnvelope};

// From<MessageEnvelope> for api types is fine (api types are local).
// The reverse direction uses free functions (orphan rule prevents From for foreign types).

impl From<MessageEnvelope> for api::MessageMetadata {
    fn from(m: MessageEnvelope) -> Self {
        Self {
            id: m.id,
            address_id: m.address_id,
            label_ids: m.label_ids,
            external_id: m.external_id,
            subject: m.subject,
            sender: api::EmailAddress {
                name: m.sender.name,
                address: m.sender.address,
            },
            to_list: m
                .to_list
                .into_iter()
                .map(|a| api::EmailAddress {
                    name: a.name,
                    address: a.address,
                })
                .collect(),
            cc_list: m
                .cc_list
                .into_iter()
                .map(|a| api::EmailAddress {
                    name: a.name,
                    address: a.address,
                })
                .collect(),
            bcc_list: m
                .bcc_list
                .into_iter()
                .map(|a| api::EmailAddress {
                    name: a.name,
                    address: a.address,
                })
                .collect(),
            reply_tos: m
                .reply_tos
                .into_iter()
                .map(|a| api::EmailAddress {
                    name: a.name,
                    address: a.address,
                })
                .collect(),
            flags: m.flags,
            time: m.time,
            size: m.size,
            unread: m.unread,
            is_replied: m.is_replied,
            is_replied_all: m.is_replied_all,
            is_forwarded: m.is_forwarded,
            num_attachments: m.num_attachments,
        }
    }
}

impl From<EmailAddress> for api::EmailAddress {
    fn from(a: EmailAddress) -> Self {
        Self {
            name: a.name,
            address: a.address,
        }
    }
}

pub fn to_envelope(m: api::MessageMetadata) -> MessageEnvelope {
    MessageEnvelope {
        id: m.id,
        address_id: m.address_id,
        label_ids: m.label_ids,
        external_id: m.external_id,
        subject: m.subject,
        sender: EmailAddress {
            name: m.sender.name,
            address: m.sender.address,
        },
        to_list: m.to_list.into_iter().map(to_email_address).collect(),
        cc_list: m.cc_list.into_iter().map(to_email_address).collect(),
        bcc_list: m.bcc_list.into_iter().map(to_email_address).collect(),
        reply_tos: m.reply_tos.into_iter().map(to_email_address).collect(),
        flags: m.flags,
        time: m.time,
        size: m.size,
        unread: m.unread,
        is_replied: m.is_replied,
        is_replied_all: m.is_replied_all,
        is_forwarded: m.is_forwarded,
        num_attachments: m.num_attachments,
    }
}

pub fn to_email_address(a: api::EmailAddress) -> EmailAddress {
    EmailAddress {
        name: a.name,
        address: a.address,
    }
}
