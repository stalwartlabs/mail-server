use std::path::PathBuf;

use import::spamassassin::import_spamassassin;

pub mod import;

fn main() {
    import_spamassassin(
        PathBuf::from("/Users/me/code/mail-server/resources/spamassassin"),
        "cf".to_string(),
        false,
    );
}

const _IGNORE: &str = r#"

[antispam]
required-score = 5
add-headers = ["X-Spam-Checker-Version: SpamAssassin _VERSION_ (_SUBVERSION_) on _HOSTNAME_",
 "X-Spam-Flag: _YESNOCAPS_", "X-Spam-Level: _STARS(*)_",
 "X-Spam-Status: _YESNO_, score=_SCORE_ required=_REQD_ tests=_TESTS_ autolearn=_AUTOLEARN_ version=_VERSION_"]
originating-ip-headers = ["X-Yahoo-Post-IP", "X-Originating-IP", "X-Apparently-From",
 "X-SenderIP X-AOL-IP", "X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp"]
rewrite-headers = ["Subject: [SPAM] _SUBJECT_"]
redirect-patterns = ["""m'/(?:index.php)?\?.*(?<=[?&])URL=(.*?)(?:$|[&\#])'i""",
 """m'^https?:/*(?:\w+\.)?google(?:\.\w{2,3}){1,2}/url\?.*?(?<=[?&])q=(.*?)(?:$|[&\#])'i""",
 """m'^https?:/*(?:\w+\.)?google(?:\.\w{2,3}){1,2}/search\?.*?(?<=[?&])q=[^&]*?(?<=%20|..[=+\s])(?:site|inurl):(.*?)(?:$|%20|[\s+&\#])'i""",
 """m'^https?:/*(?:\w+\.)?google(?:\.\w{2,3}){1,2}/search\?.*?(?<=[?&])q=[^&]*?(?<=%20|..[=+\s])(?:"|%22)(.*?)(?:$|%22|["\s+&\#])'i""",
 """m'^https?:/*(?:\w+\.)?google(?:\.\w{2,3}){1,2}/translate\?.*?(?<=[?&])u=(.*?)(?:$|[&\#])'i""",
 """m'^https?:/*(?:\w+\.)?google(?:\.\w{2,3}){1,2}/pagead/iclk\?.*?(?<=[?&])adurl=(.*?)(?:$|[&\#])'i""",
 """m'^https?:/*(?:\w+\.)?aol\.com/redir\.adp\?.*(?<=[?&])_url=(.*?)(?:$|[&\#])'i""",
 """m'^https?/*(?:\w+\.)?facebook\.com/l/;(.*)'i""",
 """/^http:\/\/chkpt\.zdnet\.com\/chkpt\/\w+\/(.*)$/i""",
 """/^http:\/\/www(?:\d+)?\.nate\.com\/r\/\w+\/(.*)$/i""",
 """/^http:\/\/.+\.gov\/(?:.*\/)?externalLink\.jhtml\?.*url=(.*?)(?:&.*)?$/i""",
 """/^http:\/\/redir\.internet\.com\/.+?\/.+?\/(.*)$/i""",
 """/^http:\/\/(?:.*?\.)?adtech\.de\/.*(?:;|\|)link=(.*?)(?:;|$)/i""",
 """m'^http.*?/redirect\.php\?.*(?<=[?&])goto=(.*?)(?:$|[&\#])'i""",
 """m'^https?:/*(?:[^/]+\.)?emf\d\.com/r\.cfm.*?&r=(.*)'i"""
]

[antispam.autolearn]
enable = true
ignore-headers = [ "X-ACL-Warn", "X-Alimail-AntiSpam", "X-Amavis-Modified", "X-Anti*", "X-aol-global-disposition",
 "X-ASF-*", "X-Assp-Version", "X-Authority-Analysis", "X-Authvirus", "X-Auto-Response-Suppress", "X-AV-Do-Run",
 "X-AV-Status", "X-avast-antispam", "X-Backend", "X-Barracuda*", "X-Bayes*", "X-BitDefender*", "X-BL", "X-Bogosity",
 "X-Boxtrapper", "X-Brightmail-Tracker", "X-BTI-AntiSpam", "X-Bugzilla-Version", "X-CanIt*", "X-Clapf-spamicity",
 "X-Cloud-Security", "X-CM-Score", "X-CMAE-*", "X-Company", "X-Coremail-Antispam", "X-CRM114-*", "X-CT-Spam",
 "X-CTCH-*", "X-Drweb-SpamState", "X-DSPAM*", "X-eavas*", "X-Enigmail-Version", "X-Eset*", "X-Exchange-Antispam-Report",
 "X-ExtloopSabreCommercials1", "X-EYOU-SPAMVALUE", "X-FB-OUTBOUND-SPAM", "X-FEAS-SBL", "X-FILTER-SCORE", "X-Forefront*",
 "X-Fuglu*", "X-getmail-filter-classifier", "X-GFIME-MASPAM", "X-Gmane-NNTP-Posting-Host", "X-GMX-Anti*", "X-He-Spam",
 "X-hMailServer-Spam", "X-IAS", "X-iGspam-global", "X-Injected-Via-Gmane", "X-Interia-Antivirus", "X-IP-Spam-Verdict",
 "X-Ironport*", "X-Junk*", "X-KLMS-*", "X-KMail-*", "X-MailCleaner-*", "X-MailFoundry", "X-MDMailLookup-Result",
 "X-ME-*", "X-MessageFilter", "X-Microsoft-Antispam", "X-Mlf-Version", "X-MXScan-*", "X-NAI-Spam-*", "X-NetStation-Status",
 "X-OVH-SPAM*", "X-PerlMx-*", "X-PFSI-Info", "X-PMX-*", "X-Policy-Service", "X-policyd-weight", "X-PreRBLs",
 "X-Probable-Spam", "X-PROLinux-SpamCheck", "X-Proofpoint-*", "x-purgate-*", "X-Qmail-Scanner-*", "X-Quarantine-ID",
 "X-RSpam-Report", "X-SA-*", "X-Scanned-by", "X-SmarterMail-CustomSpamHeader", "X-Spam*", "X-SPF-Scan-By", "X-STA-*",
 "X-StarScan-Version", "X-SurGATE-Result", "X-SWITCHham-Score", "X-UI-*", "X-Univie*", "X-Virus*", "X-VR-*",
 "X-WatchGuard*", "X-Whitelist-Domain", "X-WUM-CCI", "X_CMAE_Category" ]
threshold.ham = 0.1
threshold.spam = 12.0


"#;
