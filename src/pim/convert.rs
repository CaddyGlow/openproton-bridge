use crate::api::{calendar, contacts};

pub fn contact_to_upsert(
    contact: &contacts::Contact,
) -> Result<gluon_rs_contacts::ContactUpsert, serde_json::Error> {
    let raw_json = serde_json::to_string(contact)?;
    let cards = contact
        .cards
        .iter()
        .map(|card| gluon_rs_contacts::ContactCardUpsert {
            card_type: card.card_type as i64,
            data: card.data.clone(),
            signature: card.signature.clone(),
        })
        .collect();
    let mut emails = Vec::with_capacity(contact.metadata.contact_emails.len());
    for email in &contact.metadata.contact_emails {
        emails.push(gluon_rs_contacts::ContactEmailUpsert {
            id: email.id.clone(),
            contact_id: email.contact_id.clone(),
            email: email.email.clone(),
            name: email.name.clone(),
            kind_json: serde_json::to_string(&email.kind)?,
            defaults: email.defaults.map(|v| v as i64),
            order: email.order.map(|v| v as i64),
            label_ids_json: serde_json::to_string(&email.label_ids)?,
            last_used_time: email.last_used_time,
            raw_json: serde_json::to_string(email)?,
        });
    }
    Ok(gluon_rs_contacts::ContactUpsert {
        id: contact.metadata.id.clone(),
        uid: contact.metadata.uid.clone(),
        name: contact.metadata.name.clone(),
        size: contact.metadata.size,
        create_time: contact.metadata.create_time,
        modify_time: contact.metadata.modify_time,
        raw_json,
        cards,
        emails,
    })
}

pub fn calendar_to_upsert(
    cal: &calendar::Calendar,
) -> Result<gluon_rs_calendar::CalendarUpsert, serde_json::Error> {
    Ok(gluon_rs_calendar::CalendarUpsert {
        id: cal.id.clone(),
        name: cal.name.clone(),
        description: cal.description.clone(),
        color: cal.color.clone(),
        display: cal.display,
        calendar_type: cal.calendar_type,
        flags: cal.flags,
        raw_json: serde_json::to_string(cal)?,
    })
}

pub fn calendar_member_to_upsert(
    member: &calendar::CalendarMember,
) -> Result<gluon_rs_calendar::CalendarMemberUpsert, serde_json::Error> {
    Ok(gluon_rs_calendar::CalendarMemberUpsert {
        id: member.id.clone(),
        calendar_id: member.calendar_id.clone(),
        email: member.email.clone(),
        color: member.color.clone(),
        display: member.display,
        permissions: member.permissions as i64,
        raw_json: serde_json::to_string(member)?,
    })
}

pub fn calendar_key_to_upsert(
    key: &calendar::CalendarKey,
) -> Result<gluon_rs_calendar::CalendarKeyUpsert, serde_json::Error> {
    Ok(gluon_rs_calendar::CalendarKeyUpsert {
        id: key.id.clone(),
        calendar_id: key.calendar_id.clone(),
        passphrase_id: key.passphrase_id.clone(),
        private_key: key.private_key.clone(),
        flags: key.flags,
        raw_json: serde_json::to_string(key)?,
    })
}

pub fn calendar_settings_to_upsert(
    settings: &calendar::CalendarSettings,
) -> Result<gluon_rs_calendar::CalendarSettingsUpsert, serde_json::Error> {
    Ok(gluon_rs_calendar::CalendarSettingsUpsert {
        id: settings.id.clone(),
        calendar_id: settings.calendar_id.clone(),
        default_event_duration: settings.default_event_duration as i64,
        default_part_day_notifications_json: serde_json::to_string(
            &settings.default_part_day_notifications,
        )?,
        default_full_day_notifications_json: serde_json::to_string(
            &settings.default_full_day_notifications,
        )?,
        raw_json: serde_json::to_string(settings)?,
    })
}

pub fn calendar_event_to_upsert(
    event: &calendar::CalendarEvent,
) -> Result<gluon_rs_calendar::CalendarEventUpsert, serde_json::Error> {
    Ok(gluon_rs_calendar::CalendarEventUpsert {
        id: event.id.clone(),
        calendar_id: event.calendar_id.clone(),
        uid: event.uid.clone(),
        shared_event_id: event.shared_event_id.clone(),
        create_time: event.create_time,
        last_edit_time: event.last_edit_time,
        start_time: event.start_time,
        end_time: event.end_time,
        start_timezone: event.start_timezone.clone(),
        end_timezone: event.end_timezone.clone(),
        full_day: event.full_day as i64,
        author: event.author.clone(),
        permissions: event.permissions as i64,
        attendees_json: serde_json::to_string(&event.attendees)?,
        shared_key_packet: event.shared_key_packet.clone(),
        calendar_key_packet: event.calendar_key_packet.clone(),
        shared_events_json: serde_json::to_string(&event.shared_events)?,
        calendar_events_json: serde_json::to_string(&event.calendar_events)?,
        attendees_events_json: serde_json::to_string(&event.attendees_events)?,
        personal_events_json: serde_json::to_string(&event.personal_events)?,
        raw_json: serde_json::to_string(event)?,
    })
}
