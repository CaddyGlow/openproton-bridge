pub use gluon_rs_contacts::QueryPage;

pub use gluon_rs_calendar::CalendarEventRange;

pub(crate) fn to_calendar_page(page: QueryPage) -> gluon_rs_calendar::QueryPage {
    gluon_rs_calendar::QueryPage {
        limit: page.limit,
        offset: page.offset,
    }
}
