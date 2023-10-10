use std::collections::{HashMap, HashSet};

pub mod spamassassin;
pub mod tokenizer;
pub mod utils;

#[derive(Debug, Default, Clone)]
struct Rule {
    name: String,
    t: RuleType,
    scores: Vec<f64>,
    captured_vars: Vec<(String, usize)>,
    required_vars: HashSet<String>,
    description: HashMap<String, String>,
    priority: i32,
    flags: Vec<TestFlag>,
}

#[derive(Debug, Default, Clone)]
enum RuleType {
    Header {
        matches: HeaderMatches,
        header: Header,
        part: HeaderPart,
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
        expr: MetaExpression,
    },

    #[default]
    None,
}

#[derive(Debug, Clone, Default)]
pub struct MetaExpression {
    pub tokens: Vec<Token>,
    pub expr: String,
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

#[derive(Debug, PartialEq, Eq, Clone)]
enum TestFlag {
    Net,
    Nice,
    UserConf,
    Learn,
    NoAutoLearn,
    Publish,
    NoPublish,
    Multiple,
    NoTrim,
    DomainsOnly,
    NoSubject,
    AutoLearnBody,
    A,
    MaxHits(u32),
    DnsBlockRule(String),
}

#[derive(Debug, Default, PartialEq, Eq, PartialOrd, Ord, Clone, Hash)]
enum Header {
    #[default]
    All,
    MessageId,
    EnvelopeFrom,
    ToCc,
    Received(ReceivedPart),
    Name(String),
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash)]
enum ReceivedPart {
    From,
    FromIp,
    FromIpRev,
    By,
    For,
    Ident,
    Id,
    Protocol,
}

#[derive(Debug, Default, Clone, Copy)]
enum HeaderMatches {
    #[default]
    Matches,
    NotMatches,
    Exists,
    NotExists,
}

#[derive(Debug, Default, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash)]
enum HeaderPart {
    Name,
    Addr,
    Raw,
    #[default]
    Default,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Token {
    Tag(String),
    Number(u32),
    Logical(Logical),
    Comparator(Comparator),
    Operation(Operation),

    OpenParen,
    CloseParen,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Logical {
    And,
    Or,
    Not,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Comparator {
    Gt,
    Lt,
    Eq,
    Ge,
    Le,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Operation {
    Add,
    Multiply,
    Divide,
    Subtract,
    And,
    Or,
    Not,
}

impl Rule {
    fn score(&self) -> f64 {
        self.scores.last().copied().unwrap_or_else(|| {
            if self.is_subrule() {
                0.0
            } else if self.name.starts_with("T_") {
                0.01
            } else {
                1.0
            }
        })
    }

    fn is_subrule(&self) -> bool {
        self.name.starts_with("__")
    }
}

impl Ord for Rule {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.priority.cmp(&other.priority) {
            std::cmp::Ordering::Equal => {
                match other
                    .score()
                    .abs()
                    .partial_cmp(&self.score().abs())
                    .unwrap()
                {
                    std::cmp::Ordering::Equal => other.name.cmp(&self.name),
                    x => x,
                }
            }
            x => x,
        }
        /*let this_score = self.score();
        let other_score = other.score();

        let this_is_negative = this_score < 0.0;
        let other_is_negative = other_score < 0.0;

        if this_is_negative != other_is_negative {
            if this_is_negative {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Greater
            }
        } else {
            let this_priority = if this_score != 0.0 {
                self.priority
            } else {
                9000
            };
            let other_priority = if other_score != 0.0 {
                other.priority
            } else {
                9000
            };

            match this_priority.cmp(&other_priority) {
                std::cmp::Ordering::Equal => {
                    match other_score.abs().partial_cmp(&this_score.abs()).unwrap() {
                        std::cmp::Ordering::Equal => other.name.cmp(&self.name),
                        x => x,
                    }
                }
                x => x,
            }
        }*/
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
