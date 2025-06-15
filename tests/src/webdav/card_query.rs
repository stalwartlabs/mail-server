/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::WebDavTest;
use dav_proto::schema::property::{CardDavProperty, DavProperty, WebDavProperty};
use groupware::DavResourceName;
use hyper::StatusCode;

pub async fn test(test: &WebDavTest) {
    println!("Running REPORT addressbook-query tests...");
    let client = test.client("john");

    // Create test data
    let default_path = format!("{}/john/default/", DavResourceName::Card.base_path());
    let mut hrefs = Vec::with_capacity(3);
    for (i, vcard) in [VCARD1, VCARD2, VCARD3].iter().enumerate() {
        let href = format!("{default_path}contact-{i}.vcf",);
        client
            .request("PUT", &href, *vcard)
            .await
            .with_status(hyper::StatusCode::CREATED);
        hrefs.push(href);
    }
    let uri_sarah = hrefs[0].as_str();
    let uri_carlos = hrefs[1].as_str();
    let uri_acme = hrefs[2].as_str();

    // Test 1: RFC6352 8.6.3 example 1
    let response = client
        .request("REPORT", &default_path, QUERY1)
        .await
        .with_status(StatusCode::MULTI_STATUS)
        .with_hrefs([uri_carlos])
        .into_propfind_response(None);
    let props = response.properties(uri_carlos);
    props
        .get(DavProperty::WebDav(WebDavProperty::GetETag))
        .is_not_empty();
    props
        .get(DavProperty::CardDav(CardDavProperty::AddressData(
            Default::default(),
        )))
        .with_values([r#"BEGIN:VCARD
VERSION:4.0
FN:Carlos Rodriguez-Martinez
NICKNAME:Charlie
EMAIL;TYPE=WORK,pref:carlos.rodriguez@example-corp.com
EMAIL;TYPE=HOME:carlosrm@personalmail.example
UID:urn:uuid:e1ee798b-3d4c-41b0-b217-b9c918e4686a
END:VCARD
"#
        .replace('\n', "\r\n")
        .as_str()]);

    // Test 2: RFC6352 8.6.3 example 2
    let response = client
        .request("REPORT", &default_path, QUERY2)
        .await
        .with_status(StatusCode::MULTI_STATUS)
        .with_hrefs([uri_carlos, uri_sarah])
        .into_propfind_response(None);
    let props = response.properties(uri_carlos);
    props
        .get(DavProperty::WebDav(WebDavProperty::GetETag))
        .is_not_empty();
    props
        .get(DavProperty::CardDav(CardDavProperty::AddressData(
            Default::default(),
        )))
        .with_values([r#"BEGIN:VCARD
FN:Carlos Rodriguez-Martinez
BDAY:--0623
CATEGORIES:Marketing,Management,International
LANG;TYPE=WORK;PREF=1:es
LANG;TYPE=WORK;PREF=2:en
LANG;TYPE=WORK;PREF=3:pt
END:VCARD
"#
        .replace('\n', "\r\n")
        .as_str()]);
    let props = response.properties(uri_sarah);
    props
        .get(DavProperty::WebDav(WebDavProperty::GetETag))
        .is_not_empty();
    props
        .get(DavProperty::CardDav(CardDavProperty::AddressData(
            Default::default(),
        )))
        .with_values([r#"BEGIN:VCARD
FN:Sarah Johnson
BDAY:19850415
CATEGORIES:Work,Research,VIP
LANG;TYPE=WORK;PREF=1:en
LANG;TYPE=WORK;PREF=2:fr
END:VCARD
"#
        .replace('\n', "\r\n")
        .as_str()]);

    // Test 3: Search within parameters
    let response = client
        .request("REPORT", &default_path, QUERY3)
        .await
        .with_status(StatusCode::MULTI_STATUS)
        .with_hrefs([uri_acme])
        .into_propfind_response(None);
    let props = response.properties(uri_acme);
    props
        .get(DavProperty::CardDav(CardDavProperty::AddressData(
            Default::default(),
        )))
        .with_values([VCARD3.replace('\n', "\r\n").as_str()]);

    // Test 4: Search using limit
    client
        .request("REPORT", &default_path, QUERY4)
        .await
        .with_status(StatusCode::MULTI_STATUS)
        .with_value(
            "D:multistatus.D:response.D:status",
            "HTTP/1.1 507 Insufficient Storage",
        )
        .with_value(
            "D:multistatus.D:response.D:error.D:number-of-matches-within-limits",
            "",
        )
        .with_value(
            "D:multistatus.D:response.D:responsedescription",
            "The number of matches exceeds the limit of 2",
        )
        .with_href_count(3);

    client.delete_default_containers().await;
    test.assert_is_empty().await;
}

const QUERY1: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
   <C:addressbook-query xmlns:D="DAV:"
                     xmlns:C="urn:ietf:params:xml:ns:carddav">
     <D:prop>
       <D:getetag/>
       <C:address-data>
         <C:prop name="VERSION"/>
         <C:prop name="UID"/>
         <C:prop name="NICKNAME"/>
         <C:prop name="EMAIL"/>
         <C:prop name="FN"/>
       </C:address-data>
     </D:prop>
     <C:filter>
       <C:prop-filter name="NICKNAME">
         <C:text-match collation="i;unicode-casemap"
                       match-type="equals"
         >charlie</C:text-match>
       </C:prop-filter>
     </C:filter>
   </C:addressbook-query>"#;

const QUERY2: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
   <C:addressbook-query xmlns:D="DAV:"
                     xmlns:C="urn:ietf:params:xml:ns:carddav">
     <D:prop>
       <D:getetag/>
       <C:address-data>
         <C:prop name="FN"/>
         <C:prop name="BDAY"/>
         <C:prop name="CATEGORIES"/>
         <C:prop name="LANG"/>
       </C:address-data>
     </D:prop>
     <C:filter test="anyof">
       <C:prop-filter name="FN">
         <C:text-match collation="i;unicode-casemap"
                       match-type="contains"
         >john</C:text-match>
       </C:prop-filter>
       <C:prop-filter name="EMAIL">
         <C:text-match collation="i;unicode-casemap"
                       match-type="contains"
         >rodriguez</C:text-match>
       </C:prop-filter>
     </C:filter>
   </C:addressbook-query>"#;

const QUERY3: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
<C:addressbook-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">
  <D:prop>
    <D:getetag/>
    <C:address-data/>
  </D:prop>
  <C:filter test="anyof">
    <C:prop-filter name="ADR">
      <C:param-filter name="LABEL">
        <C:text-match collation="i;unicode-casemap" match-type="contains">enterprise</C:text-match>
      </C:param-filter>
    </C:prop-filter>
  </C:filter>
</C:addressbook-query>"#;

const QUERY4: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
   <C:addressbook-query xmlns:D="DAV:"
                     xmlns:C="urn:ietf:params:xml:ns:carddav">
     <D:prop>
       <D:getetag/>
     </D:prop>
     <C:filter test="anyof">
       <C:prop-filter name="ORG">
         <C:text-match collation="i;unicode-casemap"
                       match-type="contains"
         >acme</C:text-match>
       </C:prop-filter>
       <C:prop-filter name="ORG">
         <C:text-match collation="i;unicode-casemap"
                       match-type="contains"
         >global</C:text-match>
       </C:prop-filter>
     </C:filter>
     <C:limit>
       <C:nresults>2</C:nresults>
     </C:limit>
   </C:addressbook-query>"#;

const VCARD1: &str = r#"BEGIN:VCARD
VERSION:4.0
FN:Sarah Johnson
N:Johnson;Sarah;Marie;Dr.;Ph.D.
NICKNAME:Sadie
GENDER:F
BDAY:19850415
ANNIVERSARY:20100610
EMAIL;TYPE=work:sarah.johnson@example.com
EMAIL;TYPE=home,pref:sarahjpersonal@example.com
TEL;TYPE=cell,voice,pref:+1-555-123-4567
TEL;TYPE=work,voice:+1-555-987-6543
TEL;TYPE=home,voice:+1-555-456-7890
ADR;TYPE=work;LABEL="123 Business Ave\nSuite 400\nNew York, NY 10001\nUSA":;;123 Business Ave;New York;NY;10001;USA
ADR;TYPE=home,pref;LABEL="456 Residential St\nApt 7B\nBrooklyn, NY 11201\nUSA":;;456 Residential St;Brooklyn;NY;11201;USA
ORG:Acme Technologies Inc.;Research Department
TITLE:Senior Research Scientist
ROLE:Team Lead
CATEGORIES:Work,Research,VIP
URL;TYPE=work:https://www.example.com/staff/sjohnson
URL;TYPE=home:https://www.sarahjohnson.example.com
KEY;TYPE=PGP:https://pgp.example.com/pks/lookup?op=get&search=sarah.johnson@example.com
NOTE:Sarah prefers video calls over phone calls. Available Mon-Thu 9-5 EST.
LANG;TYPE=work;PREF=1:en
LANG;TYPE=work;PREF=2:fr
TZ:-0500
GEO:40.7128;-74.0060
UID:urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6
REV:20220315T133000Z
END:VCARD
"#;

const VCARD2: &str = r#"BEGIN:VCARD
VERSION:4.0
FN:Carlos Rodriguez-Martinez
N:Rodriguez-Martinez;Carlos;Alberto;Mr.;Jr.
NICKNAME:Charlie
GENDER:M
BDAY:--0623
ANNIVERSARY:20150809
EMAIL;TYPE=work,pref:carlos.rodriguez@example-corp.com
EMAIL;TYPE=home:carlosrm@personalmail.example
TEL;TYPE=cell,voice,pref:+34-611-234-567
TEL;TYPE=work,voice:+34-911-876-543
TEL;TYPE=home,voice:+34-644-321-987
TEL;TYPE=fax:+34-911-876-544
ADR;TYPE=work;LABEL="Calle Empresarial 42\nPlanta 3\nMadrid, 28001\nSpain":;;Calle Empresarial 42;Madrid;;28001;Spain
ADR;TYPE=home,pref;LABEL="Avenida Residencial 15\nPiso 7, Puerta C\nMadrid, 28045\nSpain":;;Avenida Residencial 15;Madrid;;28045;Spain
ORG:Global Solutions S.L.;Marketing Division
TITLE:Digital Marketing Director
ROLE:Department Head
CATEGORIES:Marketing,Management,International
URL;TYPE=work:https://www.example-corp.com/team/carlos
URL;TYPE=home:https://www.carlosrodriguez.example
URL;TYPE=social:https://linkedin.com/in/carlosrodriguezm
KEY;TYPE=PGP:https://pgp.example.com/pks/lookup?op=get&search=carlos.rodriguez@example-corp.com
NOTE:Carlos speaks English, Spanish, and Portuguese fluently. Prefers communication via email. Do not contact after 7PM CET.
LANG;TYPE=work;PREF=1:es
LANG;TYPE=work;PREF=2:en
LANG;TYPE=work;PREF=3:pt
TZ:+0100
GEO:40.4168;-3.7038
UID:urn:uuid:e1ee798b-3d4c-41b0-b217-b9c918e4686a
REV:20230712T092135Z
SOURCE:https://contacts.example.com/carlosrodriguez.vcf
KIND:individual
MEMBER:urn:uuid:03a0e51f-d1aa-4385-8a53-e29025acd8af
RELATED;TYPE=friend:urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6
END:VCARD
"#;

const VCARD3: &str = r#"BEGIN:VCARD
VERSION:4.0
FN:Acme Business Solutions Ltd.
N:;;;;
KIND:ORG
ORG:Acme Business Solutions Ltd.;Technology Division
EMAIL;TYPE=WORK,pref:info@acme-solutions.example
EMAIL;TYPE=support:support@acme-solutions.example
EMAIL;TYPE=sales:sales@acme-solutions.example
TEL;TYPE=WORK,VOICE,pref:+44-20-1234-5678
TEL;TYPE=FAX:+44-20-1234-5679
TEL;TYPE=support:+44-800-987-6543
ADR;TYPE=WORK;LABEL="10 Enterprise Way\nTech Park\nLondon, EC1A 1BB\nUnited
  Kingdom":;;10 Enterprise Way\, Tech Park;London;;EC1A 1BB;United Kingdom
ADR;TYPE=branch;LABEL="25 Innovation Street\nManchester, M1 5QF\nUnited Kin
 gdom":;;25 Innovation Street;Manchester;;M1 5QF;United Kingdom
URL;TYPE=WORK:https://www.acme-solutions.example
URL;TYPE=support:https://support.acme-solutions.example
CATEGORIES:Technology,B2B,Solutions,Services
NOTE:Business hours: Mon-Fri 9:00-17:30 GMT. Closed on UK bank holidays. VAT
  Reg: GB123456789
TZ:Z
GEO:51.5074\;-0.1278
KEY;TYPE=PGP:https://pgp.example.com/pks/lookup?op=get&search=info@acme-solu
 tions.example
UID:urn:uuid:a9e95948-7b1c-46e8-bd85-c729a9e910f2
REV:20230415T153000Z
LANG;TYPE=WORK;PREF=1:en
LANG;TYPE=WORK;PREF=2:de
LANG;TYPE=WORK;PREF=3:fr
SOURCE:https://directory.example.com/acme.vcf
RELATED;TYPE=CONTACT:urn:uuid:b9e93fdb-4d34-45fa-a1e2-47da0428c4a1
RELATED;TYPE=CONTACT:urn:uuid:c8e74dfe-6b34-45fa-b1e2-47ea0428c4b2
X-ABLabel:Company
PRODID:-//Example Corp.//Contact Manager 3.0//EN
END:VCARD
"#;
