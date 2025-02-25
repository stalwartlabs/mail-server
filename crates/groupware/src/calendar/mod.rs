use calcard::icalendar::ICalendar;
use jmap_proto::types::{acl::Acl, value::AclGrant};
use utils::map::vec_map::VecMap;

pub struct Calendar {
    pub preferences: VecMap<u32, CalendarPreferences>,
    pub acls: Vec<AclGrant>,
}

pub struct CalendarPreferences {
    pub name: String,
    pub description: Option<String>,
    pub sort_order: u32,
    pub color: Option<String>,
    pub is_subscribed: bool,
    pub is_default: bool,
    pub is_visible: bool,
    pub include_in_availability: IncludeInAvailability,
    pub default_alerts_with_time: VecMap<String, ICalendar>,
    pub default_alerts_without_time: VecMap<String, ICalendar>,
    pub time_zone: Timezone,
}

pub struct CalendarEvent {
    pub name: Option<String>,
    pub event: ICalendar,
    pub calendar_ids: Vec<u32>,
    pub user_properties: VecMap<u32, ICalendar>,
    pub created: u64,
    pub updated: u64,
    pub may_invite_self: bool,
    pub may_invite_others: bool,
    pub hide_attendees: bool,
    pub is_draft: bool,
}

pub enum Timezone {
    IANA(String),
    Custom(ICalendar),
    Default,
}

pub enum IncludeInAvailability {
    All,
    Attending,
    None,
}

pub enum CalendarRight {
    ReadFreeBusy,
    ReadItems,
    WriteAll,
    WriteOwn,
    UpdatePrivate,
    RSVP,
    Share,
    Delete,
}

impl TryFrom<Acl> for CalendarRight {
    type Error = Acl;

    fn try_from(value: Acl) -> Result<Self, Self::Error> {
        match value {
            Acl::ReadFreeBusy => Ok(CalendarRight::ReadFreeBusy),
            Acl::ReadItems => Ok(CalendarRight::ReadItems),
            Acl::Modify => Ok(CalendarRight::WriteAll),
            Acl::ModifyItemsOwn => Ok(CalendarRight::WriteOwn),
            Acl::ModifyPrivateProperties => Ok(CalendarRight::UpdatePrivate),
            Acl::RSVP => Ok(CalendarRight::RSVP),
            Acl::Share => Ok(CalendarRight::Share),
            Acl::Delete => Ok(CalendarRight::Delete),
            _ => Err(value),
        }
    }
}

impl From<CalendarRight> for Acl {
    fn from(value: CalendarRight) -> Self {
        match value {
            CalendarRight::ReadFreeBusy => Acl::ReadFreeBusy,
            CalendarRight::ReadItems => Acl::ReadItems,
            CalendarRight::WriteAll => Acl::Modify,
            CalendarRight::WriteOwn => Acl::ModifyItemsOwn,
            CalendarRight::UpdatePrivate => Acl::ModifyPrivateProperties,
            CalendarRight::RSVP => Acl::RSVP,
            CalendarRight::Share => Acl::Share,
            CalendarRight::Delete => Acl::Delete,
        }
    }
}
