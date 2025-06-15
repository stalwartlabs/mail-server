/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::KV_BAYES_MODEL_USER;
use directory::backend::internal::manage::ManageDirectory;
use imap_proto::ResponseType;
use nlp::bayes::{TokenHash, Weights};

use crate::{
    imap::Type,
    jmap::{delivery::SmtpConnection, wait_for_index},
    smtp::session::VerifyResponse,
};

use super::{IMAPTest, ImapConnection};

pub async fn test(handle: &IMAPTest) {
    println!("Running Bayes tests...");
    let mut imap = ImapConnection::connect(b"_x ").await;
    imap.assert_read(Type::Untagged, ResponseType::Ok).await;
    imap.send("AUTHENTICATE PLAIN AGJheWVzQGV4YW1wbGUuY29tAHNlY3JldA==")
        .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;

    // Make sure the bayes classifier is empty
    let account_id = handle
        .server
        .store()
        .get_principal_id("bayes@example.com")
        .await
        .unwrap()
        .unwrap();
    let w = handle.spam_weights(account_id).await;
    assert_eq!(w.ham, 0);
    assert_eq!(w.spam, 0);

    // Train the classifier via APPEND
    imap.append("INBOX", HAM[0]).await;
    imap.append("Junk Mail", SPAM[0]).await;
    let w = handle.spam_weights(account_id).await;
    assert_eq!(w.ham, 1);
    assert_eq!(w.spam, 1);

    // Append two spam samples to "Drafts", then train the classifier via STORE and MOVE
    imap.append("Drafts", SPAM[1]).await;
    imap.append("Drafts", SPAM[2]).await;
    imap.send_ok("SELECT Drafts").await;
    imap.send_ok("STORE 1 +FLAGS ($Junk)").await;
    imap.send_ok("MOVE 2 \"Junk Mail\"").await;
    let w = handle.spam_weights(account_id).await;
    assert_eq!(w.ham, 1);
    assert_eq!(w.spam, 3);

    // Add the remaining messages via APPEND
    for message in HAM.iter().skip(1) {
        imap.append("INBOX", message).await;
    }
    for message in SPAM.iter().skip(3) {
        imap.append("Junk Mail", message).await;
    }
    let w = handle.spam_weights(account_id).await;
    assert_eq!(w.ham, 10);
    assert_eq!(w.spam, 10);

    // Send 3 test emails
    for message in TEST {
        let mut lmtp = SmtpConnection::connect_port(11201).await;
        lmtp.ingest("bill@example.com", &["bayes@example.com"], message)
            .await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    imap.send_ok("SELECT INBOX").await;
    imap.send("FETCH 11 (FLAGS RFC822.TEXT)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_not_contains("FLAGS ($Junk")
        .assert_contains("Subject: can someone explain")
        .assert_contains("X-Spam-Bayes: No");
    imap.send("FETCH 12 (FLAGS RFC822.TEXT)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_not_contains("FLAGS ($Junk")
        .assert_contains("Subject: classifier test")
        .assert_not_contains("X-Spam-Bayes: ");
    imap.send_ok("SELECT \"Junk Mail\"").await;
    imap.send("FETCH 10 (FLAGS RFC822.TEXT)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("FLAGS ($Junk")
        .assert_contains("Subject: save up to")
        .assert_contains("X-Spam-Bayes: Yes");
    imap.send_ok("MOVE 10 INBOX").await;
    let w = handle.spam_weights(account_id).await;
    assert_eq!(w.ham, 11);
    assert_eq!(w.spam, 10);
}

impl ImapConnection {
    async fn append(&mut self, mailbox: &str, message: &str) {
        self.send_ok(&format!(
            "APPEND {:?} {{{}+}}\r\n{}",
            mailbox,
            message.len(),
            message
        ))
        .await;
    }

    async fn send_ok(&mut self, cmd: &str) {
        self.send(cmd).await;
        self.assert_read(Type::Tagged, ResponseType::Ok).await;
    }
}

impl IMAPTest {
    async fn spam_weights(&self, account_id: u32) -> Weights {
        wait_for_index(&self.server).await;

        self.server
            .in_memory_store()
            .counter_get(TokenHash::default().serialize_account(KV_BAYES_MODEL_USER, account_id))
            .await
            .map(Weights::from)
            .unwrap()
    }
}

const SPAM: [&str; 10] = [
    concat!(
        "Subject: save up to NUMBER on life insurance\r\n\r\n wh",
        "y spend more than you have to life quote savings e",
        "nsuring your family s financial security is very i",
        "mportant life quote savings makes buying life insu",
        "rance simple and affordable we provide free access",
        " to the very best companies and the lowest rates l",
        "ife quote savings is fast easy and saves you money",
        " let us help you get started with the best values ",
        "in the country on new coverage you can save hundre",
        "ds or even thousands of dollars by requesting a fr",
        "ee quote from lifequote savings our service will t",
        "ake you less than NUMBER minutes to complete shop ",
        "and compare save up to NUMBER on all types of life",
        " insurance hyperlink click here for your free quot",
        "e protecting your family is the best investment yo",
        "u ll ever make if you are in receipt of this email",
        " in error and or wish to be removed from our list ",
        "hyperlink please click here and type remove if you",
        " reside in any state which prohibits e mail solici",
        "tations for insurance please disregard this email\r\n",
        " \r\n"
    ),
    concat!(
        "Subject: a powerhouse gifting program\r\n\r\nyou don t ",
        "want to miss get in with the founders the major pl",
        "ayers are on this one for once be where the player",
        "s are this is your private invitation experts are ",
        "calling this the fastest way to huge cash flow eve",
        "r conceived leverage NUMBER NUMBER into NUMBER NUM",
        "BER over and over again the question here is you e",
        "ither want to be wealthy or you don t which one ar",
        "e you i am tossing you a financial lifeline and fo",
        "r your sake i hope you grab onto it and hold on ti",
        "ght for the ride of your life testimonials hear wh",
        "at average people are doing their first few days w",
        "e ve received NUMBER NUMBER in NUMBER day and we a",
        "re doing that over and over again q s in al i m a ",
        "single mother in fl and i ve received NUMBER NUMBE",
        "R in the last NUMBER days d s in fl i was not sure",
        " about this when i sent off my NUMBER NUMBER pledg",
        "e but i got back NUMBER NUMBER the very next day l",
        " l in ky i didn t have the money so i found myself",
        " a partner to work this with we have received NUMB",
        "ER NUMBER over the last NUMBER days i think i made",
        " the right decision don t you k c in fl i pick up ",
        "NUMBER NUMBER my first day and i they gave me free",
        " leads and all the training you can too j w in ca ",
        "announcing we will close your sales for you and he",
        "lp you get a fax blast immediately upon your entry",
        " you make the money free leads training don t wait",
        " call now fax back to NUMBER NUMBER NUMBER NUMBER ",
        "or call NUMBER NUMBER NUMBER NUMBER name__________",
        "________________________phone_____________________",
        "______________________ fax________________________",
        "_____________email________________________________",
        "____________ best time to call____________________",
        "_____time zone____________________________________",
        "____ this message is sent in compliance of the new",
        " e mail bill per section NUMBER paragraph a NUMBER",
        " c of s NUMBER further transmissions by the sender",
        " of this email may be stopped at no cost to you by",
        " sending a reply to this email address with the wo",
        "rd remove in the subject line errors omissions and",
        " exceptions excluded this is not spam i have compi",
        "led this list from our replicate database relative",
        " to seattle marketing group the gigt or turbo team",
        " for the sole purpose of these communications your",
        " continued inclusion is only by your gracious perm",
        "ission if you wish to not receive this mail from m",
        "e please send an email to tesrewinter URL with rem",
        "ove in the subject and you will be deleted immedia",
        "tely\r\n\r\n"
    ),
    concat!(
        "Subject: help wanted \r\n\r\nwe are a NUMBER year old f",
        "ortune NUMBER company that is growing at a tremend",
        "ous rate we are looking for individuals who want t",
        "o work from home this is an opportunity to make an",
        " excellent income no experience is required we wil",
        "l train you so if you are looking to be employed f",
        "rom home with a career that has vast opportunities",
        " then go URL we are looking for energetic and self",
        " motivated people if that is you than click on the",
        " link and fill out the form and one of our employe",
        "ment specialist will contact you to be removed fro",
        "m our link simple go to URL \r\n\r\n"
    ),
    concat!(
        "Subject: tired of the bull out there\r\n\r\n want to st",
        "op losing money want a real money maker receive NU",
        "MBER NUMBER NUMBER NUMBER today experts are callin",
        "g this the fastest way to huge cash flow ever conc",
        "eived a powerhouse gifting program you don t want ",
        "to miss we work as a team this is your private inv",
        "itation get in with the founders this is where the",
        " big boys play the major players are on this one f",
        "or once be where the players are this is a system ",
        "that will drive NUMBER NUMBER s to your doorstep i",
        "n a short period of time leverage NUMBER NUMBER in",
        "to NUMBER NUMBER over and over again the question ",
        "here is you either want to be wealthy or you don t",
        " which one are you i am tossing you a financial li",
        "feline and for your sake i hope you grab onto it a",
        "nd hold on tight for the ride of your life testimo",
        "nials hear what average people are doing their fir",
        "st few days we ve received NUMBER NUMBER in NUMBER",
        " day and we are doing that over and over again q s",
        " in al i m a single mother in fl and i ve received",
        " NUMBER NUMBER in the last NUMBER days d s in fl i",
        " was not sure about this when i sent off my NUMBER",
        " NUMBER pledge but i got back NUMBER NUMBER the ve",
        "ry next day l l in ky i didn t have the money so i",
        " found myself a partner to work this with we have ",
        "received NUMBER NUMBER over the last NUMBER days i",
        " think i made the right decision don t you k c in ",
        "fl i pick up NUMBER NUMBER my first day and i they",
        " gave me free leads and all the training you can t",
        "oo j w in ca this will be the most important call ",
        "you make this year free leads training announcing ",
        "we will close your sales for you and help you get ",
        "a fax blast immediately upon your entry you make t",
        "he money free leads training don t wait call now N",
        "UMBER NUMBER NUMBER NUMBER print and fax to NUMBER",
        " NUMBER NUMBER NUMBER or send an email requesting ",
        "more information to successleads URL please includ",
        "e your name and telephone number receive NUMBER NU",
        "MBER free leads just for responding a NUMBER NUMBE",
        "R value name___________________________________ ph",
        "one___________________________________ fax________",
        "_____________________________ email_______________",
        "____________________ this message is sent in compl",
        "iance of the new e mail bill per section NUMBER pa",
        "ragraph a NUMBER c of s NUMBER further transmissio",
        "ns by the sender of this email may be stopped at n",
        "o cost to you by sending a reply to this email add",
        "ress with the word remove in the subject line erro",
        "rs omissions and exceptions excluded this is not s",
        "pam i have compiled this list from our replicate d",
        "atabase relative to seattle marketing group the gi",
        "gt or turbo team for the sole purpose of these com",
        "munications your continued inclusion is only by yo",
        "ur gracious permission if you wish to not receive ",
        "this mail from me please send an email to tesrewin",
        "ter URL with remove in the subject and you will be",
        " deleted immediately\r\n\r\n"
    ),
    concat!(
        "Subject: cellular phone accessories \r\n\r\n all at bel",
        "ow wholesale prices http NUMBER NUMBER NUMBER NUMB",
        "ER NUMBER sites merchant sales hands free ear buds",
        " NUMBER NUMBER phone holsters NUMBER NUMBER booste",
        "r antennas only NUMBER NUMBER phone cases NUMBER N",
        "UMBER car chargers NUMBER NUMBER face plates as lo",
        "w as NUMBER NUMBER lithium ion batteries as low as",
        " NUMBER NUMBER http NUMBER NUMBER NUMBER NUMBER NU",
        "MBER sites merchant sales click below for accessor",
        "ies on all nokia motorola lg nextel samsung qualco",
        "mm ericsson audiovox phones at below wholesale pri",
        "ces http NUMBER NUMBER NUMBER NUMBER NUMBER sites ",
        "merchant sales if you need assistance please call ",
        "us NUMBER NUMBER NUMBER to be removed from future ",
        "mailings please send your remove request to remove",
        " me now NUMBER URL thank you and have a super day\r\n",
        " \r\n"
    ),
    concat!(
        "Subject: conferencing made easy\r\n\r\n only NUMBER cen",
        "ts per minute including long distance no setup fee",
        "s no contracts or monthly fees call anytime from a",
        "nywhere to anywhere connects up to NUMBER particip",
        "ants simplicity in set up and administration opera",
        "tor help available NUMBER NUMBER the highest quali",
        "ty service for the lowest rate in the industry fil",
        "l out the form below to find out how you can lower",
        " your phone bill every month required input field ",
        "name web address company name state business phone",
        " home phone email address type of business to be r",
        "emoved from our distribution lists please hyperlin",
        "k click here\r\n\r\n"
    ),
    concat!(
        "Subject: dear friend\r\n\r\n i am mrs sese seko widow o",
        "f late president mobutu sese seko of zaire now kno",
        "wn as democratic republic of congo drc i am moved ",
        "to write you this letter this was in confidence co",
        "nsidering my presentcircumstance and situation i e",
        "scaped along with my husband and two of our sons g",
        "eorge kongolo and basher out of democratic republi",
        "c of congo drc to abidjan cote d ivoire where my f",
        "amily and i settled while we later moved to settle",
        "d in morroco where my husband later died of cancer",
        " disease however due to this situation we decided ",
        "to changed most of my husband s billions of dollar",
        "s deposited in swiss bank and other countries into",
        " other forms of money coded for safe purpose becau",
        "se the new head of state of dr mr laurent kabila h",
        "as made arrangement with the swiss government and ",
        "other european countries to freeze all my late hus",
        "band s treasures deposited in some european countr",
        "ies hence my children and i decided laying low in ",
        "africa to study the situation till when things get",
        "s better like now that president kabila is dead an",
        "d the son taking over joseph kabila one of my late",
        " husband s chateaux in southern france was confisc",
        "ated by the french government and as such i had to",
        " change my identity so that my investment will not",
        " be traced and confiscated i have deposited the su",
        "m eighteen million united state dollars us NUMBER ",
        "NUMBER NUMBER NUMBER with a security company for s",
        "afekeeping the funds are security coded to prevent",
        " them from knowing the content what i want you to ",
        "do is to indicate your interest that you will assi",
        "st us by receiving the money on our behalf acknowl",
        "edge this message so that i can introduce you to m",
        "y son kongolo who has the out modalities for the c",
        "laim of the said funds i want you to assist in inv",
        "esting this money but i will not want my identity ",
        "revealed i will also want to buy properties and st",
        "ock in multi national companies and to engage in o",
        "ther safe and non speculative investments may i at",
        " this point emphasise the high level of confidenti",
        "ality which this business demands and hope you wil",
        "l not betray the trust and confidence which i repo",
        "se in you in conclusion if you want to assist us m",
        "y son shall put you in the picture of the business",
        " tell you where the funds are currently being main",
        "tained and also discuss other modalities including",
        " remunerationfor your services for this reason kin",
        "dly furnish us your contact information that is yo",
        "ur personal telephone and fax number for confident",
        "ial URL regards mrs m sese seko\r\n\r\n"
    ),
    concat!(
        "Subject: lowest rates available for term life insu",
        "rance\r\n\r\n take a moment and fill out our online for",
        "m to see the low rate you qualify for save up to N",
        "UMBER from regular rates smokers accepted URL repr",
        "esenting quality nationwide carriers act now to ea",
        "sily remove your address from the list go to URL p",
        "lease allow NUMBER NUMBER hours for removal\r\n\r\n"
    ),
    concat!(
        "Subject: central bank of nigeria foreign remittanc",
        "e \r\n\r\n dept tinubu square lagos nigeria email smith",
        "_j URL NUMBERth of august NUMBER attn president ce",
        "o strictly private business proposal i am mr johns",
        "on s abu the bills and exchange director at the fo",
        "reignremittance department of the central bank of ",
        "nigeria i am writingyou this letter to ask for you",
        "r support and cooperation to carrying thisbusiness",
        " opportunity in my department we discovered abando",
        "ned the sumof us NUMBER NUMBER NUMBER NUMBER thirt",
        "y seven million four hundred thousand unitedstates",
        " dollars in an account that belong to one of our f",
        "oreign customers an american late engr john creek ",
        "junior an oil merchant with the federal government",
        " of nigeria who died along with his entire family ",
        "of a wifeand two children in kenya airbus aNUMBER ",
        "NUMBER flight kqNUMBER in novemberNUMBER since we ",
        "heard of his death we have been expecting his next",
        " of kin tocome over and put claims for his money a",
        "s the heir because we cannotrelease the fund from ",
        "his account unless someone applies for claims asth",
        "e next of kin to the deceased as indicated in our ",
        "banking guidelines unfortunately neither their fam",
        "ily member nor distant relative hasappeared to cla",
        "im the said fund upon this discovery i and other o",
        "fficialsin my department have agreed to make busin",
        "ess with you release the totalamount into your acc",
        "ount as the heir of the fund since no one came for",
        "it or discovered either maintained account with ou",
        "r bank other wisethe fund will be returned to the ",
        "bank treasury as unclaimed fund we have agreed tha",
        "t our ratio of sharing will be as stated thus NUMB",
        "ER for you as foreign partner and NUMBER for us th",
        "e officials in my department upon the successful c",
        "ompletion of this transfer my colleague and i will",
        "come to your country and mind our share it is from",
        " our NUMBER we intendto import computer accessorie",
        "s into my country as way of recycling thefund to c",
        "ommence this transaction we require you to immedia",
        "tely indicateyour interest by calling me or sendin",
        "g me a fax immediately on the abovetelefax and enc",
        "lose your private contact telephone fax full namea",
        "nd address and your designated banking co ordinate",
        "s to enable us fileletter of claim to the appropri",
        "ate department for necessary approvalsbefore the t",
        "ransfer can be made note also this transaction mus",
        "t be kept strictly confidential becauseof its natu",
        "re nb please remember to give me your phone and fa",
        "x no mr johnson smith abu irish linux users group ",
        "ilug URL URL for un subscription information list ",
        "maintainer listmaster URL\r\n\r\n"
    ),
    concat!(
        "Subject: dear stuart\r\n\r\n are you tired of searching",
        " for love in all the wrong places find love now at",
        " URL URL browse through thousands of personals in ",
        "your area join for free URL search e mail chat use",
        " URL to meet cool guys and hot girls go NUMBER on ",
        "NUMBER or use our private chat rooms click on the ",
        "link to get started URL find love now you have rec",
        "eived this email because you have registerd with e",
        "mailrewardz or subscribed through one of our marke",
        "ting partners if you have received this message in",
        " error or wish to stop receiving these great offer",
        "s please click the remove link above to unsubscrib",
        "e from these mailings please click here URL\r\n\r\n"
    ),
];

const HAM: [&str; 10] = [
    concat!(
        "Message-ID: <mid1@foobar.org>\r\nSubject: i have been",
        " trying to research via sa mirrors and search engi",
        "nes\r\n\r\nif a canned script exists giving clients acce",
        "ss to their user_prefs options via a web based cgi",
        " interface numerous isps provide this feature to c",
        "lients but so far i can find nothing our configura",
        "tion uses amavis postfix and clamav for virus filt",
        "ering and procmail with spamassassin for spam filt",
        "ering i would prefer not to have to write a script",
        " myself but will appreciate any suggestions this U",
        "RL email is sponsored by osdn tired of that same o",
        "ld cell phone get a new here for free URL ________",
        "_______________________________________ spamassass",
        "in talk mailing list spamassassin talk URL URL\r\n\r\n"
    ),
    concat!(
        "Message-ID: mid2@foobar.org\r\nSubject: hello\r\n\r\nhave y",
        "ou seen and discussed this article and his approac",
        "h thank you URL hell there are no rules here we re",
        " trying to accomplish something thomas alva edison",
        " this URL email is sponsored by osdn tired of that",
        " same old cell phone get a new here for free URL _",
        "______________________________________________ spa",
        "massassin devel mailing list spamassassin devel UR",
        "L URL \r\n\r\n"
    ),
    concat!(
        "Message-ID: <mid3@foobar.org>\r\nSubject: hi all apol",
        "ogies for the possible silly question\r\n\r\ni don t thi",
        "nk it is but but is eircom s adsl service nat ed a",
        "nd what implications would that have for voip i kn",
        "ow there are difficulties with voip or connecting ",
        "to clients connected to a nat ed network from the ",
        "internet wild i e machines with static real ips an",
        "y help pointers would be helpful cheers rgrds bern",
        "ard bernard tyers national centre for sensor resea",
        "rch p NUMBER NUMBER NUMBER NUMBER e bernard tyers ",
        "URL w URL l nNUMBER ______________________________",
        "_________________ iiu mailing list iiu URL URL \r\n\r\n"
    ),
    concat!(
        "Message-ID: <mid4@foobar.org>\r\nSubject: can someone",
        " explain\r\n\r\nwhat type of operating system solaris is",
        " as ive never seen or used it i dont know wheather",
        " to get a server from sun or from dell i would pre",
        "fer a linux based server and sun seems to be the o",
        "ne for that but im not sure if solaris is a distro",
        " of linux or a completely different operating syst",
        "em can someone explain kiall mac innes irish linux",
        " users group ilug URL URL for un subscription info",
        "rmation list maintainer listmaster URL \r\n\r\n"
    ),
    concat!(
        "Message-ID: <mid5@foobar.org>\r\nSubject: folks my fi",
        "rst time posting\r\n\r\nhave a bit of unix experience bu",
        "t am new to linux just got a new pc at home dell b",
        "ox with windows xp added a second hard disk for li",
        "nux partitioned the disk and have installed suse N",
        "UMBER NUMBER from cd which went fine except it did",
        "n t pick up my monitor i have a dell branded eNUMB",
        "ERfpp NUMBER lcd flat panel monitor and a nvidia g",
        "eforceNUMBER tiNUMBER video card both of which are",
        " probably too new to feature in suse s default set",
        " i downloaded a driver from the nvidia website and",
        " installed it using rpm then i ran saxNUMBER as wa",
        "s recommended in some postings i found on the net ",
        "but it still doesn t feature my video card in the ",
        "available list what next another problem i have a ",
        "dell branded keyboard and if i hit caps lock twice",
        " the whole machine crashes in linux not windows ev",
        "en the on off switch is inactive leaving me to rea",
        "ch for the power cable instead if anyone can help ",
        "me in any way with these probs i d be really grate",
        "ful i ve searched the net but have run out of idea",
        "s or should i be going for a different version of ",
        "linux such as redhat opinions welcome thanks a lot",
        " peter irish linux users group ilug URL URL for un",
        " subscription information list maintainer listmast",
        "er URL\r\n\r\n"
    ),
    concat!(
        "Message-ID: <mid6@foobar.org>\r\nSubject: has anyone\r\n",
        "\r\nseen heard of used some package that would let a ",
        "random person go to a webpage create a mailing lis",
        "t then administer that list also of course let ppl",
        " sign up for the lists and manage their subscripti",
        "ons similar to the old URL but i d like to have it",
        " running on my server not someone elses chris URL ",
        "\r\n\r\n"
    ),
    concat!(
        "Message-ID: <mid7@foobar.org>\r\nSubject: hi thank yo",
        "u for the useful replies\r\n\r\ni have found some intere",
        "sting tutorials in the ibm developer connection UR",
        "L and URL registration is needed i will post the s",
        "ame message on the web application security list a",
        "s suggested by someone for now i thing i will use ",
        "mdNUMBER for password checking i will use the appr",
        "oach described in secure programmin fo linux and u",
        "nix how to i will separate the authentication modu",
        "le so i can change its implementation at anytime t",
        "hank you again mario torre please avoid sending me",
        " word or powerpoint attachments see URL \r\n\r\n"
    ),
    concat!(
        "Message-ID: <mid8@foobar.org>\r\nSubject: hehe sorry\r\n",
        "\r\nbut if you hit caps lock twice the computer crash",
        "es theres one ive never heard before have you trye",
        "d dell support yet i think dell computers prefer r",
        "edhat dell provide some computers pre loaded with ",
        "red hat i dont know for sure tho so get someone el",
        "ses opnion as well as mine original message from i",
        "lug admin URL mailto ilug admin URL on behalf of p",
        "eter staunton sent NUMBER august NUMBER NUMBER NUM",
        "BER to ilug URL subject ilug newbie seeks advice s",
        "use NUMBER NUMBER folks my first time posting have",
        " a bit of unix experience but am new to linux just",
        " got a new pc at home dell box with windows xp add",
        "ed a second hard disk for linux partitioned the di",
        "sk and have installed suse NUMBER NUMBER from cd w",
        "hich went fine except it didn t pick up my monitor",
        " i have a dell branded eNUMBERfpp NUMBER lcd flat ",
        "panel monitor and a nvidia geforceNUMBER tiNUMBER ",
        "video card both of which are probably too new to f",
        "eature in suse s default set i downloaded a driver",
        " from the nvidia website and installed it using rp",
        "m then i ran saxNUMBER as was recommended in some ",
        "postings i found on the net but it still doesn t f",
        "eature my video card in the available list what ne",
        "xt another problem i have a dell branded keyboard ",
        "and if i hit caps lock twice the whole machine cra",
        "shes in linux not windows even the on off switch i",
        "s inactive leaving me to reach for the power cable",
        " instead if anyone can help me in any way with the",
        "se probs i d be really grateful i ve searched the ",
        "net but have run out of ideas or should i be going",
        " for a different version of linux such as redhat o",
        "pinions welcome thanks a lot peter irish linux use",
        "rs group ilug URL URL for un subscription informat",
        "ion list maintainer listmaster URL irish linux use",
        "rs group ilug URL URL for un subscription informat",
        "ion list maintainer listmaster URL\r\n\r\n"
    ),
    concat!(
        "Message-ID: <mid9@foobar.org>\r\nSubject: it will fun",
        "ction as a router\r\n\r\nif that is what you wish it eve",
        "n looks like the modem s embedded os is some kind ",
        "of linux being that it has interesting interfaces ",
        "like ethNUMBER i don t use it as a router though i",
        " just have it do the absolute minimum dsl stuff an",
        "d do all the really fun stuff like pppoe on my lin",
        "ux box also the manual tells you what the default ",
        "password is don t forget to run pppoe over the alc",
        "atel speedtouch NUMBERi as in my case you have to ",
        "have a bridge configured in the router modem s sof",
        "tware this lists your vci values etc also does any",
        "one know if the high end speedtouch with NUMBER et",
        "hernet ports can act as a full router or do i stil",
        "l need to run a pppoe stack on the linux box regar",
        "ds vin irish linux users group ilug URL URL for un",
        " subscription information list maintainer listmast",
        "er URL irish linux users group ilug URL URL for un",
        " subscription information list maintainer listmast",
        "er URL \r\n\r\n"
    ),
    concat!(
        "Message-ID: <mid10@foobar.org>\r\nSubject: all is it ",
        "just me\r\n\r\nor has there been a massive increase in t",
        "he amount of email being falsely bounced around th",
        "e place i ve already received email from a number ",
        "of people i don t know asking why i am sending the",
        "m email these can be explained by servers from rus",
        "sia and elsewhere coupled with the false emails i ",
        "received myself it s really starting to annoy me a",
        "m i the only one seeing an increase in recent week",
        "s martin martin whelan déise design URL tel NUMBE",
        "R NUMBER our core product déiseditor allows organ",
        "isations to publish information to their web site ",
        "in a fast and cost effective manner there is no ne",
        "ed for a full time web developer as the site can b",
        "e easily updated by the organisations own staff in",
        "stant updates to keep site information fresh sites",
        " which are updated regularly bring users back visi",
        "t URL for a demonstration déiseditor managing you",
        "r information ____________________________________",
        "___________ iiu mailing list iiu URL URL ,0\r\n"
    ),
];

const TEST: [&str; 3] = [
    concat!(
        "Subject: save up to NUMBER on life insurance\r\n\r\nwhy ",
        "spend more than you have to life quote savings ens",
        "uring your family s financial security is very imp",
        "ortant life quote savings makes buying life insura",
        "nce simple and affordable we provide free access t",
        "o the very best companies and the lowest rates lif",
        "e quote savings is fast easy and saves you money l",
        "et us help you get started with the best values in",
        " the country on new coverage you can save hundreds",
        " or even thousands of dollars by requesting a free",
        " quote from lifequote savings our service will tak",
        "e you less than NUMBER minutes to complete shop an",
        "d compare save up to NUMBER on all types of life i",
        "nsurance hyperlink click here for your free quote ",
        "protecting your family is the best investment you ",
        "ll ever make if you are in receipt of this email i",
        "n error and or wish to be removed from our list hy",
        "perlink please click here and type remove if you r",
        "eside in any state which prohibits e mail solicita",
        "tions for insurance please disregard this email\r\n"
    ),
    concat!(
        "Subject: can someone explain\r\n\r\nwhat type of operati",
        "ng system solaris is as ive never seen or used it ",
        "i dont know wheather to get a server from sun or f",
        "rom dell i would prefer a linux based server and s",
        "un seems to be the one for that but im not sure if",
        " solaris is a distro of linux or a completely diff",
        "erent operating system can someone explain kiall m",
        "ac innes irish linux users group ilug URL URL for ",
        "un subscription information list maintainer listma",
        "ster URL \r\n"
    ),
    concat!(
        "Subject: classifier test\r\n\r\nthis is a novel text tha",
        "t the bayes classifier has never seen before, it s",
        "hould be classified as ham or non-ham\r\n"
    ),
];
