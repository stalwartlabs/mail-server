use std::collections::HashMap;

pub mod meta;
pub mod spamassassin;
pub mod utils;

#[derive(Debug, Default)]
struct Rule {
    name: String,
    t: RuleType,
    scores: Vec<f64>,
    description: HashMap<String, String>,
    priority: i32,
    flags: Vec<TestFlag>,
}

#[derive(Debug, Default)]
enum RuleType {
    Header {
        matches: HeaderMatches,
        header: Header,
        if_unset: Option<String>,
        pattern: String,
    },
    Body {
        pattern: String,
        raw: bool,
    },
    Full {
        pattern: String,
    },
    Uri {
        pattern: String,
    },
    Eval {
        function: String,
        params: Vec<String>,
    },
    Meta {
        tokens: Vec<Token>,
    },

    #[default]
    None,
}

impl RuleType {
    pub fn pattern(&mut self) -> Option<&mut String> {
        match self {
            RuleType::Header { pattern, .. } => Some(pattern),
            RuleType::Body { pattern, .. } => Some(pattern),
            RuleType::Full { pattern, .. } => Some(pattern),
            RuleType::Uri { pattern, .. } => Some(pattern),
            _ => None,
        }
    }
}

#[derive(Debug)]
enum TestFlag {
    Net,
    Nice,
    UserConf,
    Learn,
    NoAutoLearn,
    Publish,
    Multiple,
    NoTrim,
    DomainsOnly,
    NoSubject,
    AutoLearnBody,
    A,
    MaxHits(u32),
    DnsBlockRule(String),
}

#[derive(Debug, Default)]
enum Header {
    #[default]
    All,
    MessageId,
    AllExternal,
    EnvelopeFrom,
    ToCc,
    Name {
        name: String,
        part: Vec<HeaderPart>,
    },
}

#[derive(Debug, Default)]
enum HeaderMatches {
    #[default]
    Matches,
    NotMatches,
    Exists,
}

#[derive(Debug, Default)]
enum HeaderPart {
    Name,
    Addr,
    #[default]
    Raw,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Token {
    Tag(String),
    Number(u32),
    And,
    Or,
    Not,
    Gt,
    Lt,
    Eq,
    Ge,
    Le,
    OpenParen,
    CloseParen,
    Add,
    Multiply,
    Divide,
}

impl Rule {
    fn score(&self) -> f64 {
        self.scores.last().copied().unwrap_or_else(|| {
            if self.name.starts_with("__") {
                0.0
            } else if self.name.starts_with("T_") {
                0.01
            } else {
                1.0
            }
        })
    }
}

impl Ord for Rule {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.priority.cmp(&other.priority) {
            std::cmp::Ordering::Equal => match self.score().partial_cmp(&other.score()).unwrap() {
                std::cmp::Ordering::Equal => other.name.cmp(&self.name),
                x => x,
            },
            x => x,
        }
    }
}

impl PartialOrd for Rule {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Rule {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.priority == other.priority && self.scores == other.scores
    }
}

impl Eq for Rule {}

pub trait UnwrapResult<T> {
    fn unwrap_result(self, action: &str) -> T;
}

impl<T> UnwrapResult<T> for Option<T> {
    fn unwrap_result(self, message: &str) -> T {
        match self {
            Some(result) => result,
            None => {
                eprintln!("Failed to {}", message);
                std::process::exit(1);
            }
        }
    }
}

impl<T, E: std::fmt::Display> UnwrapResult<T> for Result<T, E> {
    fn unwrap_result(self, message: &str) -> T {
        match self {
            Ok(result) => result,
            Err(err) => {
                eprintln!("Failed to {}: {}", message, err);
                std::process::exit(1);
            }
        }
    }
}
