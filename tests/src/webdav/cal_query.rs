/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::WebDavTest;
use ahash::AHashSet;
use calcard::{
    common::timezone::Tz,
    icalendar::{ICalendar, dates::CalendarEvent},
};
use dav_proto::schema::property::TimeRange;
use groupware::{
    DavResourceName,
    calendar::{CalendarEventData, alarm::ExpandAlarm},
};
use hyper::StatusCode;
use store::write::serialize::rkyv_unarchive;

pub async fn test(test: &WebDavTest) {
    println!("Running REPORT calendar-query & free-busy-query tests...");
    let client = test.client("john");
    let cal_path = format!("{}/john/default/", DavResourceName::Cal.base_path());

    #[allow(clippy::never_loop)]
    for (num, ics) in [
        (1, ICAL_RFC_ABCD1_ICS),
        (2, ICAL_RFC_ABCD2_ICS),
        (3, ICAL_RFC_ABCD3_ICS),
        (4, ICAL_RFC_ABCD4_ICS),
        (5, ICAL_RFC_ABCD5_ICS),
        (6, ICAL_RFC_ABCD6_ICS),
        (7, ICAL_RFC_ABCD7_ICS),
        (8, ICAL_RFC_ABCD8_ICS),
    ] {
        roundtrip_expansion(ics, false);
        client
            .request("PUT", &rfc_file_name(num), ics)
            .await
            .with_status(StatusCode::CREATED);
    }

    // Test 1: Partial Retrieval of Events by Time Range
    let response = client
        .request("REPORT", &cal_path, REPORT_1)
        .await
        .with_status(StatusCode::MULTI_STATUS)
        .with_hrefs([rfc_file_name(2).as_str(), rfc_file_name(3).as_str()])
        .into_propfind_response(None);
    response
        .properties(&rfc_file_name(2))
        .calendar_data()
        .with_values([REPORT_1_EXPECTED_ABCD2.replace('\n', "\r\n").as_str()]);
    response
        .properties(&rfc_file_name(3))
        .calendar_data()
        .with_values([REPORT_1_EXPECTED_ABCD3.replace('\n', "\r\n").as_str()]);

    // Test 2: Partial Retrieval of Recurring Events
    let response = client
        .request("REPORT", &cal_path, REPORT_2)
        .await
        .with_status(StatusCode::MULTI_STATUS)
        .with_hrefs([rfc_file_name(2).as_str(), rfc_file_name(3).as_str()])
        .into_propfind_response(None);
    response
        .properties(&rfc_file_name(2))
        .calendar_data()
        .with_values([REPORT_2_EXPECTED_ABCD2.replace('\n', "\r\n").as_str()]);
    response
        .properties(&rfc_file_name(3))
        .calendar_data()
        .with_values([REPORT_2_EXPECTED_ABCD3.replace('\n', "\r\n").as_str()]);

    // Test 3: Expanded Retrieval of Recurring Events
    let response = client
        .request("REPORT", &cal_path, REPORT_3)
        .await
        .with_status(StatusCode::MULTI_STATUS)
        .with_hrefs([rfc_file_name(2).as_str(), rfc_file_name(3).as_str()])
        .into_propfind_response(None);
    response
        .properties(&rfc_file_name(2))
        .calendar_data()
        .with_values([REPORT_3_EXPECTED_ABCD2.replace('\n', "\r\n").as_str()]);
    response
        .properties(&rfc_file_name(3))
        .calendar_data()
        .with_values([REPORT_3_EXPECTED_ABCD3.replace('\n', "\r\n").as_str()]);

    // Test 4: Partial Retrieval of Stored Free Busy Components
    let response = client
        .request("REPORT", &cal_path, REPORT_4)
        .await
        .with_status(StatusCode::MULTI_STATUS)
        .with_hrefs([rfc_file_name(8).as_str()])
        .into_propfind_response(None);
    response
        .properties(&rfc_file_name(8))
        .calendar_data()
        .with_values([REPORT_4_EXPECTED_ABCD8.replace('\n', "\r\n").as_str()]);

    // Test 5: Retrieval of To-Dos by Alarm Time Range
    let response = client
        .request("REPORT", &cal_path, REPORT_5)
        .await
        .with_status(StatusCode::MULTI_STATUS)
        .with_hrefs([rfc_file_name(5).as_str()])
        .into_propfind_response(None);
    response
        .properties(&rfc_file_name(5))
        .calendar_data()
        .with_values([ICAL_RFC_ABCD5_ICS.replace('\n', "\r\n").as_str()]);

    // Test 6: Retrieval of Event by UID
    client
        .request("REPORT", &cal_path, REPORT_6)
        .await
        .with_status(StatusCode::MULTI_STATUS)
        .with_hrefs([rfc_file_name(3).as_str()])
        .into_propfind_response(None);

    // Test 7: Retrieval of Events by PARTSTAT
    client
        .request("REPORT", &cal_path, REPORT_7)
        .await
        .with_status(StatusCode::MULTI_STATUS)
        .with_hrefs([rfc_file_name(3).as_str()])
        .into_propfind_response(None);

    // Test 8: Retrieval of Events Only
    client
        .request("REPORT", &cal_path, REPORT_8)
        .await
        .with_status(StatusCode::MULTI_STATUS)
        .with_hrefs([
            rfc_file_name(1).as_str(),
            rfc_file_name(2).as_str(),
            rfc_file_name(3).as_str(),
        ])
        .into_propfind_response(None);

    // Test 9: Retrieval of All Pending To-Dos
    client
        .request("REPORT", &cal_path, REPORT_9)
        .await
        .with_status(StatusCode::MULTI_STATUS)
        .with_hrefs([rfc_file_name(4).as_str(), rfc_file_name(5).as_str()])
        .into_propfind_response(None);

    // Test 10: Successful CALDAV:free-busy-query REPORT
    assert_eq!(
        remove_dtstamp(
            client
                .request("REPORT", &cal_path, REPORT_10)
                .await
                .with_status(StatusCode::OK)
                .body
                .as_ref()
                .unwrap()
        ),
        remove_dtstamp(REPORT_10_RESPONSE)
    );
    assert_eq!(
        remove_dtstamp(
            client
                .request("REPORT", &cal_path, REPORT_11)
                .await
                .with_status(StatusCode::OK)
                .body
                .as_ref()
                .unwrap()
        ),
        remove_dtstamp(REPORT_11_RESPONSE)
    );

    client.delete_default_containers().await;
    test.assert_is_empty().await;
}

#[test]
#[ignore]
fn ical_roundtrip_expansion() {
    for entry in std::fs::read_dir("/Users/me/code/calcard/resources/ical").unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "ics") {
            println!("Testing: {:?}", path);
            let input = match String::from_utf8(std::fs::read(&path).unwrap()) {
                Ok(input) => input,
                Err(err) => {
                    // ISO-8859-1
                    err.as_bytes()
                        .iter()
                        .map(|&b| b as char)
                        .collect::<String>()
                }
            };
            roundtrip_expansion(&input, true);
        }
    }
}

fn roundtrip_expansion(ics: &str, ignore_errors: bool) {
    let ical = if let Ok(ical) = ICalendar::parse(ics) {
        ical
    } else if ignore_errors {
        return;
    } else {
        panic!("Failed to parse ICalendar {}", ics);
    };
    let expanded = ical.expand_dates(Tz::UTC, 100);
    if !ignore_errors {
        assert!(expanded.errors.is_empty());
    }
    let mut min_utc = i64::MAX;
    let mut max_utc = i64::MIN;
    let mut events = expanded
        .events
        .into_iter()
        .map(|e| {
            let e = e.try_into_date_time().unwrap();
            let start = e.start.timestamp();
            let end = e.end.timestamp();
            let mut min = std::cmp::min(start, end);
            let mut max = std::cmp::max(start, end);

            for alarm in ical.alarms_for_id(e.comp_id) {
                if let Some(alarm_time) = alarm
                    .expand_alarm(0, 0)
                    .and_then(|alarm| alarm.delta.to_timestamp(start, end, Tz::UTC))
                {
                    if alarm_time < min {
                        min = alarm_time;
                    }

                    if alarm_time > max {
                        max = alarm_time;
                    }
                }
            }

            if min < min_utc {
                min_utc = min;
            }
            if max > max_utc {
                max_utc = max;
            }
            CalendarEvent {
                comp_id: e.comp_id,
                start,
                end,
            }
        })
        .collect::<Vec<_>>();

    // Verify min/max UTC timestamps
    let event_data = CalendarEventData::new(ical, Tz::UTC, 100, &mut None);
    let from_time = event_data.base_time_utc as i64 + event_data.base_offset;
    let to_time = from_time + event_data.duration as i64;

    if min_utc != i64::MAX {
        assert_eq!(
            from_time,
            min_utc,
            "diff: {}, failed for {}",
            from_time - min_utc,
            ics
        );
        assert_eq!(
            to_time,
            max_utc,
            "diff: {}, failed for {}",
            to_time - max_utc,
            ics
        );
    }

    // Validate archive expansion
    let expanded_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&event_data).unwrap();
    let expanded_archive = rkyv_unarchive::<CalendarEventData>(&expanded_bytes).unwrap();
    let mut events_archive = expanded_archive
        .expand(
            Tz::UTC,
            TimeRange {
                start: i64::MIN,
                end: i64::MAX,
            },
        )
        .unwrap();
    events.sort_by(|a, b| {
        if a.comp_id == b.comp_id {
            a.start.cmp(&b.start)
        } else {
            a.comp_id.cmp(&b.comp_id)
        }
    });
    events_archive.sort_by(|a, b| {
        if a.comp_id == b.comp_id {
            a.start.cmp(&b.start)
        } else {
            a.comp_id.cmp(&b.comp_id)
        }
    });

    assert_eq!(events, events_archive);
}

fn rfc_file_name(num: usize) -> String {
    format!(
        "{}/john/default/abcd{num}.ics",
        DavResourceName::Cal.base_path()
    )
}

const REPORT_1: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
   <C:calendar-query xmlns:D="DAV:"
                 xmlns:C="urn:ietf:params:xml:ns:caldav">
     <D:prop>
       <D:getetag/>
       <C:calendar-data>
         <C:comp name="VCALENDAR">
           <C:prop name="VERSION"/>
           <C:comp name="VEVENT">
             <C:prop name="SUMMARY"/>
             <C:prop name="UID"/>
             <C:prop name="DTSTART"/>
             <C:prop name="DTEND"/>
             <C:prop name="DURATION"/>
             <C:prop name="RRULE"/>
             <C:prop name="RDATE"/>
             <C:prop name="EXRULE"/>
             <C:prop name="EXDATE"/>
             <C:prop name="RECURRENCE-ID"/>
           </C:comp>
           <C:comp name="VTIMEZONE"/>
         </C:comp>
       </C:calendar-data>
     </D:prop>
     <C:filter>
       <C:comp-filter name="VCALENDAR">
         <C:comp-filter name="VEVENT">
           <C:time-range start="20060104T000000Z"
                         end="20060105T000000Z"/>
         </C:comp-filter>
       </C:comp-filter>
     </C:filter>
   </C:calendar-query>
"#;

const REPORT_1_EXPECTED_ABCD2: &str = r#"BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Example Corp.//CalDAV Client//EN
BEGIN:VTIMEZONE
LAST-MODIFIED:20040110T032845Z
TZID:US/Eastern
BEGIN:DAYLIGHT
DTSTART:20000404T020000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=4
TZNAME:EDT
TZOFFSETFROM:-0500
TZOFFSETTO:-0400
END:DAYLIGHT
BEGIN:STANDARD
DTSTART:20001026T020000
RRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=10
TZNAME:EST
TZOFFSETFROM:-0400
TZOFFSETTO:-0500
END:STANDARD
END:VTIMEZONE
BEGIN:VEVENT
DTSTART;TZID=US/Eastern:20060102T120000
DURATION:PT1H
RRULE:FREQ=DAILY;COUNT=5
SUMMARY:Event #2
UID:00959BC664CA650E933C892C@example.com
END:VEVENT
BEGIN:VEVENT
DTSTART;TZID=US/Eastern:20060104T140000
DURATION:PT1H
RECURRENCE-ID;TZID=US/Eastern:20060104T120000
SUMMARY:Event #2 bis
UID:00959BC664CA650E933C892C@example.com
END:VEVENT
BEGIN:VEVENT
DTSTART;TZID=US/Eastern:20060106T140000
DURATION:PT1H
RECURRENCE-ID;TZID=US/Eastern:20060106T120000
SUMMARY:Event #2 bis bis
UID:00959BC664CA650E933C892C@example.com
END:VEVENT
END:VCALENDAR
"#;

const REPORT_1_EXPECTED_ABCD3: &str = r#"BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Example Corp.//CalDAV Client//EN
BEGIN:VTIMEZONE
LAST-MODIFIED:20040110T032845Z
TZID:US/Eastern
BEGIN:DAYLIGHT
DTSTART:20000404T020000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=4
TZNAME:EDT
TZOFFSETFROM:-0500
TZOFFSETTO:-0400
END:DAYLIGHT
BEGIN:STANDARD
DTSTART:20001026T020000
RRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=10
TZNAME:EST
TZOFFSETFROM:-0400
TZOFFSETTO:-0500
END:STANDARD
END:VTIMEZONE
BEGIN:VEVENT
DTSTART;TZID=US/Eastern:20060104T100000
DURATION:PT1H
SUMMARY:Event #3
UID:DC6C50A017428C5216A2F1CD@example.com
END:VEVENT
END:VCALENDAR
"#;

const REPORT_2: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
   <C:calendar-query xmlns:D="DAV:"
                     xmlns:C="urn:ietf:params:xml:ns:caldav">
     <D:prop>
       <C:calendar-data>
         <C:limit-recurrence-set start="20060103T000000Z"
                                 end="20060105T000000Z"/>
       </C:calendar-data>
     </D:prop>
     <C:filter>
       <C:comp-filter name="VCALENDAR">
         <C:comp-filter name="VEVENT">
           <C:time-range start="20060103T000000Z"
                         end="20060105T000000Z"/>
         </C:comp-filter>
       </C:comp-filter>
     </C:filter>
   </C:calendar-query>
"#;

const REPORT_2_EXPECTED_ABCD2: &str = r#"BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Example Corp.//CalDAV Client//EN
BEGIN:VTIMEZONE
LAST-MODIFIED:20040110T032845Z
TZID:US/Eastern
BEGIN:DAYLIGHT
DTSTART:20000404T020000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=4
TZNAME:EDT
TZOFFSETFROM:-0500
TZOFFSETTO:-0400
END:DAYLIGHT
BEGIN:STANDARD
DTSTART:20001026T020000
RRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=10
TZNAME:EST
TZOFFSETFROM:-0400
TZOFFSETTO:-0500
END:STANDARD
END:VTIMEZONE
BEGIN:VEVENT
DTSTAMP:20060206T001121Z
DTSTART;TZID=US/Eastern:20060102T120000
DURATION:PT1H
RRULE:FREQ=DAILY;COUNT=5
SUMMARY:Event #2
UID:00959BC664CA650E933C892C@example.com
END:VEVENT
BEGIN:VEVENT
DTSTAMP:20060206T001121Z
DTSTART;TZID=US/Eastern:20060104T140000
DURATION:PT1H
RECURRENCE-ID;TZID=US/Eastern:20060104T120000
SUMMARY:Event #2 bis
UID:00959BC664CA650E933C892C@example.com
END:VEVENT
END:VCALENDAR
"#;

const REPORT_2_EXPECTED_ABCD3: &str = r#"BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Example Corp.//CalDAV Client//EN
BEGIN:VTIMEZONE
LAST-MODIFIED:20040110T032845Z
TZID:US/Eastern
BEGIN:DAYLIGHT
DTSTART:20000404T020000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=4
TZNAME:EDT
TZOFFSETFROM:-0500
TZOFFSETTO:-0400
END:DAYLIGHT
BEGIN:STANDARD
DTSTART:20001026T020000
RRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=10
TZNAME:EST
TZOFFSETFROM:-0400
TZOFFSETTO:-0500
END:STANDARD
END:VTIMEZONE
BEGIN:VEVENT
ATTENDEE;PARTSTAT=ACCEPTED;ROLE=CHAIR:mailto:cyrus@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION:mailto:lisa@example.com
DTSTAMP:20060206T001220Z
DTSTART;TZID=US/Eastern:20060104T100000
DURATION:PT1H
LAST-MODIFIED:20060206T001330Z
ORGANIZER:mailto:cyrus@example.com
SEQUENCE:1
STATUS:TENTATIVE
SUMMARY:Event #3
UID:DC6C50A017428C5216A2F1CD@example.com
X-ABC-GUID:E1CX5Dr-0007ym-Hz@example.com
END:VEVENT
END:VCALENDAR
"#;

const REPORT_3: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
   <C:calendar-query xmlns:D="DAV:"
                     xmlns:C="urn:ietf:params:xml:ns:caldav">
     <D:prop>
       <C:calendar-data>
         <C:comp name="VCALENDAR">
           <C:comp name="VEVENT"/>
         </C:comp>
         <C:expand start="20060103T000000Z"
                   end="20060105T000000Z"/>
       </C:calendar-data>
     </D:prop>
     <C:filter>
       <C:comp-filter name="VCALENDAR">
         <C:comp-filter name="VEVENT">
           <C:time-range start="20060103T000000Z"
                         end="20060105T000000Z"/>
         </C:comp-filter>
       </C:comp-filter>
     </C:filter>
   </C:calendar-query>
"#;

const REPORT_3_EXPECTED_ABCD2: &str = r#"BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Example Corp.//CalDAV Client//EN
BEGIN:VEVENT
DTSTART:20060103T170000Z
RECURRENCE-ID:20060103T170000Z
DTSTAMP:20060206T001121Z
DURATION:PT1H
SUMMARY:Event #2
UID:00959BC664CA650E933C892C@example.com
END:VEVENT
BEGIN:VEVENT
DTSTART:20060104T190000Z
RECURRENCE-ID:20060104T190000Z
DTSTAMP:20060206T001121Z
DURATION:PT1H
SUMMARY:Event #2 bis
UID:00959BC664CA650E933C892C@example.com
END:VEVENT
END:VCALENDAR
"#;

const REPORT_3_EXPECTED_ABCD3: &str = r#"BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Example Corp.//CalDAV Client//EN
BEGIN:VEVENT
DTSTART:20060104T150000Z
ATTENDEE;PARTSTAT=ACCEPTED;ROLE=CHAIR:mailto:cyrus@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION:mailto:lisa@example.com
DTSTAMP:20060206T001220Z
DURATION:PT1H
LAST-MODIFIED:20060206T001330Z
ORGANIZER:mailto:cyrus@example.com
SEQUENCE:1
STATUS:TENTATIVE
SUMMARY:Event #3
UID:DC6C50A017428C5216A2F1CD@example.com
X-ABC-GUID:E1CX5Dr-0007ym-Hz@example.com
END:VEVENT
END:VCALENDAR
"#;

const REPORT_4: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
   <C:calendar-query xmlns:D="DAV:"
                 xmlns:C="urn:ietf:params:xml:ns:caldav">
     <D:prop>
       <C:calendar-data>
         <C:limit-freebusy-set start="20060102T000000Z"
                                 end="20060103T000000Z"/>
       </C:calendar-data>
     </D:prop>
     <C:filter>
       <C:comp-filter name="VCALENDAR">
         <C:comp-filter name="VFREEBUSY">
           <C:time-range start="20060102T000000Z"
                           end="20060103T000000Z"/>
         </C:comp-filter>
       </C:comp-filter>
     </C:filter>
   </C:calendar-query>
"#;

const REPORT_4_EXPECTED_ABCD8: &str = r#"BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Example Corp.//CalDAV Client//EN
BEGIN:VFREEBUSY
ORGANIZER;CN="Bernard Desruisseaux":mailto:bernard@example.com
UID:76ef34-54a3d2@example.com
DTSTAMP:20050530T123421Z
DTSTART:20060101T000000Z
DTEND:20060108T000000Z
FREEBUSY;FBTYPE=BUSY-TENTATIVE:20060102T100000Z/20060102T120000Z
END:VFREEBUSY
END:VCALENDAR
"#;

const REPORT_5: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
   <C:calendar-query xmlns:C="urn:ietf:params:xml:ns:caldav">
     <D:prop xmlns:D="DAV:">
       <D:getetag/>
       <C:calendar-data/>
     </D:prop>
     <C:filter>
       <C:comp-filter name="VCALENDAR">
         <C:comp-filter name="VTODO">
           <C:comp-filter name="VALARM">
             <C:time-range start="20060106T100000Z"
                             end="20060107T100000Z"/>
           </C:comp-filter>
         </C:comp-filter>
       </C:comp-filter>
     </C:filter>
   </C:calendar-query>
"#;

const REPORT_6: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
   <C:calendar-query xmlns:C="urn:ietf:params:xml:ns:caldav">
     <D:prop xmlns:D="DAV:">
       <D:getetag/>
       <C:calendar-data/>
     </D:prop>
     <C:filter>
       <C:comp-filter name="VCALENDAR">
         <C:comp-filter name="VEVENT">
           <C:prop-filter name="UID">
             <C:text-match collation="i;octet"
             >DC6C50A017428C5216A2F1CD@example.com</C:text-match>
           </C:prop-filter>
         </C:comp-filter>
       </C:comp-filter>
     </C:filter>
   </C:calendar-query>
"#;

const REPORT_7: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
   <C:calendar-query xmlns:C="urn:ietf:params:xml:ns:caldav">
     <D:prop xmlns:D="DAV:">
       <D:getetag/>
       <C:calendar-data/>
     </D:prop>
     <C:filter>
       <C:comp-filter name="VCALENDAR">
         <C:comp-filter name="VEVENT">
           <C:prop-filter name="ATTENDEE">
             <C:text-match collation="i;ascii-casemap"
              >mailto:lisa@example.com</C:text-match>
             <C:param-filter name="PARTSTAT">
               <C:text-match collation="i;ascii-casemap"
                >NEEDS-ACTION</C:text-match>
             </C:param-filter>
           </C:prop-filter>
         </C:comp-filter>
       </C:comp-filter>
     </C:filter>
   </C:calendar-query>
"#;

const REPORT_8: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
   <C:calendar-query xmlns:C="urn:ietf:params:xml:ns:caldav">
     <D:prop xmlns:D="DAV:">
       <D:getetag/>
       <C:calendar-data/>
     </D:prop>
     <C:filter>
       <C:comp-filter name="VCALENDAR">
         <C:comp-filter name="VEVENT"/>
       </C:comp-filter>
     </C:filter>
   </C:calendar-query>
"#;

const REPORT_9: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
   <C:calendar-query xmlns:C="urn:ietf:params:xml:ns:caldav">
     <D:prop xmlns:D="DAV:">
       <D:getetag/>
       <C:calendar-data/>
     </D:prop>
     <C:filter>
       <C:comp-filter name="VCALENDAR">
         <C:comp-filter name="VTODO">
           <C:prop-filter name="COMPLETED">
             <C:is-not-defined/>
           </C:prop-filter>
           <C:prop-filter name="STATUS">
             <C:text-match
                negate-condition="yes">CANCELLED</C:text-match>
           </C:prop-filter>
         </C:comp-filter>
       </C:comp-filter>
     </C:filter>
   </C:calendar-query>
"#;

const REPORT_10: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
   <C:free-busy-query xmlns:C="urn:ietf:params:xml:ns:caldav">
     <C:time-range start="20060104T140000Z"
                     end="20060105T220000Z"/>
   </C:free-busy-query>
"#;

const REPORT_10_RESPONSE: &str = r#"BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Stalwart Labs LLC//Stalwart Server//EN
BEGIN:VFREEBUSY
DTSTART:20060104T140000Z
DTEND:20060105T220000Z
FREEBUSY;FBTYPE=BUSY-TENTATIVE:20060104T150000Z/20060104T160000Z
FREEBUSY;FBTYPE=BUSY:20060104T190000Z/20060104T200000Z;20060105T170000Z/20060105T180000Z
FREEBUSY;FBTYPE=BUSY-UNAVAILABLE:20060105T100000Z/20060105T120000Z
END:VFREEBUSY
END:VCALENDAR
"#;

const REPORT_11: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
   <C:free-busy-query xmlns:C="urn:ietf:params:xml:ns:caldav">
     <C:time-range start="20060101T000000Z"
                     end="20060104T140000Z"/>
   </C:free-busy-query>
"#;

const REPORT_11_RESPONSE: &str = r#"BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Stalwart Labs LLC//Stalwart Server//EN
BEGIN:VFREEBUSY
DTSTART:20060101T000000Z
DTEND:20060104T140000Z
DTSTAMP:20250505T105255Z
FREEBUSY;FBTYPE=BUSY-TENTATIVE:20060102T100000Z/20060102T120000Z
FREEBUSY;FBTYPE=BUSY:20060102T150000Z/20060102T160000Z;20060102T170000Z/20060102T180000Z;
 20060103T100000Z/20060103T120000Z;20060103T170000Z/20060103T180000Z;20060104T100000Z/20060104T120000Z
END:VFREEBUSY
END:VCALENDAR
"#;

const ICAL_RFC_ABCD1_ICS: &str = r#"BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Example Corp.//CalDAV Client//EN
BEGIN:VTIMEZONE
LAST-MODIFIED:20040110T032845Z
TZID:US/Eastern
BEGIN:DAYLIGHT
DTSTART:20000404T020000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=4
TZNAME:EDT
TZOFFSETFROM:-0500
TZOFFSETTO:-0400
END:DAYLIGHT
BEGIN:STANDARD
DTSTART:20001026T020000
RRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=10
TZNAME:EST
TZOFFSETFROM:-0400
TZOFFSETTO:-0500
END:STANDARD
END:VTIMEZONE
BEGIN:VEVENT
DTSTAMP:20060206T001102Z
DTSTART;TZID=US/Eastern:20060102T100000
DURATION:PT1H
SUMMARY:Event #1
Description:Go Steelers!
UID:74855313FA803DA593CD579A@example.com
END:VEVENT
END:VCALENDAR
"#;

const ICAL_RFC_ABCD2_ICS: &str = r#"BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Example Corp.//CalDAV Client//EN
BEGIN:VTIMEZONE
LAST-MODIFIED:20040110T032845Z
TZID:US/Eastern
BEGIN:DAYLIGHT
DTSTART:20000404T020000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=4
TZNAME:EDT
TZOFFSETFROM:-0500
TZOFFSETTO:-0400
END:DAYLIGHT
BEGIN:STANDARD
DTSTART:20001026T020000
RRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=10
TZNAME:EST
TZOFFSETFROM:-0400
TZOFFSETTO:-0500
END:STANDARD
END:VTIMEZONE
BEGIN:VEVENT
DTSTAMP:20060206T001121Z
DTSTART;TZID=US/Eastern:20060102T120000
DURATION:PT1H
RRULE:FREQ=DAILY;COUNT=5
SUMMARY:Event #2
UID:00959BC664CA650E933C892C@example.com
END:VEVENT
BEGIN:VEVENT
DTSTAMP:20060206T001121Z
DTSTART;TZID=US/Eastern:20060104T140000
DURATION:PT1H
RECURRENCE-ID;TZID=US/Eastern:20060104T120000
SUMMARY:Event #2 bis
UID:00959BC664CA650E933C892C@example.com
END:VEVENT
BEGIN:VEVENT
DTSTAMP:20060206T001121Z
DTSTART;TZID=US/Eastern:20060106T140000
DURATION:PT1H
RECURRENCE-ID;TZID=US/Eastern:20060106T120000
SUMMARY:Event #2 bis bis
UID:00959BC664CA650E933C892C@example.com
END:VEVENT
END:VCALENDAR
"#;

const ICAL_RFC_ABCD3_ICS: &str = r#"BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Example Corp.//CalDAV Client//EN
BEGIN:VTIMEZONE
LAST-MODIFIED:20040110T032845Z
TZID:US/Eastern
BEGIN:DAYLIGHT
DTSTART:20000404T020000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=4
TZNAME:EDT
TZOFFSETFROM:-0500
TZOFFSETTO:-0400
END:DAYLIGHT
BEGIN:STANDARD
DTSTART:20001026T020000
RRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=10
TZNAME:EST
TZOFFSETFROM:-0400
TZOFFSETTO:-0500
END:STANDARD
END:VTIMEZONE
BEGIN:VEVENT
ATTENDEE;PARTSTAT=ACCEPTED;ROLE=CHAIR:mailto:cyrus@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION:mailto:lisa@example.com
DTSTAMP:20060206T001220Z
DTSTART;TZID=US/Eastern:20060104T100000
DURATION:PT1H
LAST-MODIFIED:20060206T001330Z
ORGANIZER:mailto:cyrus@example.com
SEQUENCE:1
STATUS:TENTATIVE
SUMMARY:Event #3
UID:DC6C50A017428C5216A2F1CD@example.com
X-ABC-GUID:E1CX5Dr-0007ym-Hz@example.com
END:VEVENT
END:VCALENDAR
"#;

const ICAL_RFC_ABCD4_ICS: &str = r#"BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Example Corp.//CalDAV Client//EN
BEGIN:VTODO
DTSTAMP:20060205T235335Z
DUE;VALUE=DATE:20060104
STATUS:NEEDS-ACTION
SUMMARY:Task #1
UID:DDDEEB7915FA61233B861457@example.com
BEGIN:VALARM
ACTION:AUDIO
TRIGGER;RELATED=START:-PT10M
END:VALARM
END:VTODO
END:VCALENDAR
"#;

const ICAL_RFC_ABCD5_ICS: &str = r#"BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Example Corp.//CalDAV Client//EN
BEGIN:VTODO
DTSTAMP:20060205T235300Z
DUE;TZID=US/Eastern:20060106T120000
LAST-MODIFIED:20060205T235308Z
SEQUENCE:1
STATUS:NEEDS-ACTION
SUMMARY:Task #2
UID:E10BA47467C5C69BB74E8720@example.com
BEGIN:VALARM
ACTION:AUDIO
TRIGGER;RELATED=START:-PT10M
END:VALARM
END:VTODO
END:VCALENDAR
"#;

const ICAL_RFC_ABCD6_ICS: &str = r#"BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Example Corp.//CalDAV Client//EN
BEGIN:VTODO
COMPLETED:20051223T122322Z
DTSTAMP:20060205T235400Z
DUE;VALUE=DATE:20051225
LAST-MODIFIED:20060205T235308Z
SEQUENCE:1
STATUS:COMPLETED
SUMMARY:Task #3
UID:E10BA47467C5C69BB74E8722@example.com
END:VTODO
END:VCALENDAR
"#;

const ICAL_RFC_ABCD7_ICS: &str = r#"BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Example Corp.//CalDAV Client//EN
BEGIN:VTODO
DTSTAMP:20060205T235600Z
DUE;VALUE=DATE:20060101
LAST-MODIFIED:20060205T235308Z
SEQUENCE:1
STATUS:CANCELLED
SUMMARY:Task #4
UID:E10BA47467C5C69BB74E8725@example.com
END:VTODO
END:VCALENDAR
"#;

const ICAL_RFC_ABCD8_ICS: &str = r#"BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Example Corp.//CalDAV Client//EN
BEGIN:VFREEBUSY
ORGANIZER;CN="Bernard Desruisseaux":mailto:bernard@example.com
UID:76ef34-54a3d2@example.com
DTSTAMP:20050530T123421Z
DTSTART:20060101T000000Z
DTEND:20060108T000000Z
FREEBUSY:20050531T230000Z/20050601T010000Z
FREEBUSY;FBTYPE=BUSY-TENTATIVE:20060102T100000Z/20060102T120000Z
FREEBUSY:20060103T100000Z/20060103T120000Z
FREEBUSY:20060104T100000Z/20060104T120000Z
FREEBUSY;FBTYPE=BUSY-UNAVAILABLE:20060105T100000Z/20060105T120000Z
FREEBUSY:20060106T100000Z/20060106T120000Z
END:VFREEBUSY
END:VCALENDAR
"#;

fn remove_dtstamp(ics: &str) -> AHashSet<String> {
    let mut result = AHashSet::new();
    for line in ics.lines() {
        if !line.starts_with("DTSTAMP:") {
            result.insert(line.to_string());
        }
    }
    result
}
