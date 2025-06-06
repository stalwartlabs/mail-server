/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashMap;
use std::{hash::Hash, str::FromStr};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Template<T> {
    pub items: Vec<TemplateItem<T>>,
    pub size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateItem<T> {
    Static(String),
    Variable(T),
    If { variable: T, block_end: usize },
    ForEach { variable: T, block_end: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Variable<T: Eq + Hash, V: AsRef<str>> {
    Single(V),
    Block(Vec<AHashMap<T, V>>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Variables<T: Eq + Hash, V: AsRef<str>> {
    pub items: AHashMap<T, Variable<T, V>>,
}

impl<T: FromStr + Eq + Hash + std::fmt::Debug> Template<T> {
    pub fn parse(mut template: &str) -> Result<Self, String> {
        let mut items = Vec::new();
        let mut block_stack = vec![];
        let mut size = 0;

        loop {
            if let Some((start, end)) = template.split_once("{{") {
                if !start.is_empty() {
                    items.push(TemplateItem::Static(start.to_string()));
                    size += start.len();
                }
                let (var, rest) = end.split_once("}}").ok_or("Unmatched {{")?;
                template = rest;
                let var = var.trim();
                if let Some(var_name) = var.strip_prefix("#").map(|v| v.trim()) {
                    let (is_each, var_name) = if let Some(each) = var_name.strip_prefix("each ") {
                        (true, each)
                    } else if let Some(if_cond) = var_name.strip_prefix("if ") {
                        (false, if_cond)
                    } else {
                        return Err(format!("Invalid block start: {}", var_name));
                    };
                    let var = T::from_str(var_name)
                        .map_err(|_| format!("Invalid variable: {}", var_name))?;

                    block_stack.push((var_name, items.len()));

                    if is_each {
                        items.push(TemplateItem::ForEach {
                            variable: var,
                            block_end: 0,
                        });
                    } else {
                        items.push(TemplateItem::If {
                            variable: var,
                            block_end: 0,
                        });
                    }
                } else if let Some(var_name) = var.strip_prefix("/").map(|v| v.trim()) {
                    let (is_each, var_name) = if let Some(each) = var_name.strip_prefix("each ") {
                        (true, each)
                    } else if let Some(if_cond) = var_name.strip_prefix("if ") {
                        (false, if_cond)
                    } else {
                        return Err(format!("Invalid block end: {}", var_name));
                    };

                    if let Some((expected_name, if_pos)) = block_stack.pop() {
                        if expected_name != var_name {
                            return Err(format!(
                                "Block end does not match start: expected {}, got {}",
                                expected_name, var_name
                            ));
                        }
                        let block_end_idx = items.len();
                        match &mut items[if_pos] {
                            TemplateItem::If { block_end, .. } if !is_each => {
                                *block_end = block_end_idx;
                            }
                            TemplateItem::ForEach { block_end, .. } if is_each => {
                                *block_end = block_end_idx;
                            }
                            _ => {
                                return Err(format!(
                                    "Block end does not match start type for {}",
                                    var_name
                                ));
                            }
                        }
                    }
                } else {
                    let var = T::from_str(var).map_err(|_| format!("Invalid variable: {}", var))?;
                    items.push(TemplateItem::Variable(var));
                }
            } else {
                if !template.is_empty() {
                    items.push(TemplateItem::Static(template.to_string()));
                    size += template.len();
                }
                break;
            }
        }

        if block_stack.is_empty() {
            Ok(Template { items, size })
        } else {
            Err(format!("Unmatched {{: {}", block_stack.last().unwrap().0))
        }
    }

    pub fn eval<V>(&self, variables: &Variables<T, V>) -> String
    where
        V: AsRef<str>,
    {
        let mut result = String::with_capacity(self.size);
        let mut items = self.items.iter().enumerate();
        let mut base_offset = 0;

        while let Some((idx, item)) = items.next() {
            let idx = idx + base_offset;
            match item {
                TemplateItem::Static(s) => result.push_str(s),
                TemplateItem::Variable(variable) => {
                    if let Some(Variable::Single(variable)) = variables.items.get(variable) {
                        html_escape(&mut result, variable.as_ref())
                    }
                }
                TemplateItem::If {
                    variable,
                    block_end,
                } => {
                    if !variables.items.contains_key(variable) {
                        items = self.items[*block_end..].iter().enumerate();
                        base_offset = *block_end;
                    }
                }
                TemplateItem::ForEach {
                    variable,
                    block_end,
                } => {
                    if let Some(Variable::Block(entries)) = variables.items.get(variable) {
                        let slice = &self.items[idx + 1..*block_end];
                        for entry in entries {
                            for sub_item in slice {
                                match sub_item {
                                    TemplateItem::Static(s) => result.push_str(s),
                                    TemplateItem::Variable(var) => {
                                        if let Some(variable) = entry.get(var) {
                                            html_escape(&mut result, variable.as_ref())
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    items = self.items[*block_end..].iter().enumerate();
                    base_offset = *block_end;
                }
            }
        }

        result
    }
}

fn html_escape(result: &mut String, input: &str) {
    for c in input.chars() {
        match c {
            '&' => result.push_str("&amp;"),
            '<' => result.push_str("&lt;"),
            '>' => result.push_str("&gt;"),
            '"' => result.push_str("&quot;"),
            '\'' => result.push_str("&#39;"),
            _ => result.push(c),
        }
    }
}

impl<T: Eq + Hash, V: AsRef<str>> Variables<T, V> {
    pub fn new() -> Self {
        Self {
            items: AHashMap::new(),
        }
    }

    pub fn insert_single(&mut self, key: T, value: V) {
        self.items.insert(key, Variable::Single(value));
    }

    pub fn insert_block<V1, V2>(&mut self, key: T, value: V1)
    where
        V1: IntoIterator<Item = V2>,
        V2: IntoIterator<Item = (T, V)>,
    {
        self.items.insert(
            key,
            Variable::Block(value.into_iter().map(AHashMap::from_iter).collect()),
        );
    }
}

impl<T: Eq + Hash, V: AsRef<str>> Default for Variables<T, V> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_variable_substitution() {
        let template = Template::parse("Hello {{name}}!").unwrap();
        let mut vars = Variables::<String, String>::new();
        vars.insert_single("name".to_string(), "World".to_string());

        let result = template.eval(&vars);
        assert_eq!(result, "Hello World!");
    }

    #[test]
    fn test_multiple_variables() {
        let template = Template::parse("{{greeting}} {{name}}, today is {{day}}").unwrap();
        let mut vars = Variables::<String, String>::new();
        vars.insert_single("greeting".to_string(), "Hello".to_string());
        vars.insert_single("name".to_string(), "Alice".to_string());
        vars.insert_single("day".to_string(), "Monday".to_string());

        let result = template.eval(&vars);
        assert_eq!(result, "Hello Alice, today is Monday");
    }

    #[test]
    fn test_missing_variable() {
        let template = Template::parse("Hello {{name}}!").unwrap();
        let vars = Variables::<String, String>::new();

        let result = template.eval(&vars);
        assert_eq!(result, "Hello !");
    }

    #[test]
    fn test_static_text_only() {
        let template = Template::parse("This is just static text").unwrap();
        let vars = Variables::<String, String>::new();

        let result = template.eval(&vars);
        assert_eq!(result, "This is just static text");
    }

    #[test]
    fn test_empty_template() {
        let template = Template::parse("").unwrap();
        let vars = Variables::<String, String>::new();

        let result = template.eval(&vars);
        assert_eq!(result, "");
    }

    #[test]
    fn test_if_block_with_existing_variable() {
        let template =
            Template::parse("{{#if show_message}}Hello World!{{/if show_message}}").unwrap();
        let mut vars = Variables::<String, String>::new();
        vars.insert_single("show_message".to_string(), "true".to_string());

        let result = template.eval(&vars);
        assert_eq!(result, "Hello World!");
    }

    #[test]
    fn test_if_block_with_missing_variable() {
        let template =
            Template::parse("{{#if show_message}}Hello World!{{/if show_message}}").unwrap();
        let vars = Variables::<String, String>::new();

        let result = template.eval(&vars);
        assert_eq!(result, "");
    }

    #[test]
    fn test_if_block_with_content_and_variables() {
        let template = Template::parse(
            "{{#if notifications}}You have notifications: {{count}}{{/if notifications}}",
        )
        .unwrap();
        let mut vars = Variables::<String, String>::new();
        vars.insert_single("notifications".to_string(), "true".to_string());
        vars.insert_single("count".to_string(), "5".to_string());

        let result = template.eval(&vars);
        assert_eq!(result, "You have notifications: 5");
    }

    #[test]
    fn test_foreach_block_basic() {
        let template = Template::parse("{{#each items}}{{name}} {{/each items}}").unwrap();
        let mut vars = Variables::<String, String>::new();

        let items = vec![
            vec![("name".to_string(), "Item1".to_string())],
            vec![("name".to_string(), "Item2".to_string())],
            vec![("name".to_string(), "Item3".to_string())],
        ];
        vars.insert_block("items".to_string(), items);

        let result = template.eval(&vars);
        assert_eq!(result, "Item1 Item2 Item3 ");
    }

    #[test]
    fn test_foreach_block_multiple_variables() {
        let template = Template::parse(
            "{{#each notifications}}* {{name}} at {{time}}\n{{/each notifications}}",
        )
        .unwrap();
        let mut vars = Variables::<String, String>::new();

        let notifications = vec![
            vec![
                ("name".to_string(), "Meeting".to_string()),
                ("time".to_string(), "10:00".to_string()),
            ],
            vec![
                ("name".to_string(), "Call".to_string()),
                ("time".to_string(), "14:30".to_string()),
            ],
        ];
        vars.insert_block("notifications".to_string(), notifications);

        let result = template.eval(&vars);
        assert_eq!(result, "* Meeting at 10:00\n* Call at 14:30\n");
    }

    #[test]
    fn test_foreach_block_empty() {
        let template = Template::parse("{{#each items}}{{name}}{{/each items}}").unwrap();
        let mut vars = Variables::<String, String>::new();
        vars.insert_block("items".to_string(), Vec::<Vec<(String, String)>>::new());

        let result = template.eval(&vars);
        assert_eq!(result, "");
    }

    #[test]
    fn test_foreach_block_missing_variable() {
        let template = Template::parse("{{#each items}}{{name}}{{/each items}}").unwrap();
        let vars = Variables::<String, String>::new();

        let result = template.eval(&vars);
        assert_eq!(result, "");
    }

    #[test]
    fn test_complex_template_example() {
        let template_str = r#"Hello {{name}},

{{#if notifications}}You have the following notifications:
{{#each notifications}}* {{name}} at {{time}}
{{/each notifications}}{{/if notifications}}
Best regards"#;

        let template = Template::parse(template_str).unwrap();
        let mut vars = Variables::<String, String>::new();
        vars.insert_single("name".to_string(), "Alice".to_string());
        vars.insert_single("notifications".to_string(), "true".to_string());

        let notifications = vec![
            vec![
                ("name".to_string(), "Team Meeting".to_string()),
                ("time".to_string(), "09:00".to_string()),
            ],
            vec![
                ("name".to_string(), "Doctor Appointment".to_string()),
                ("time".to_string(), "15:30".to_string()),
            ],
        ];
        vars.insert_block("notifications".to_string(), notifications);

        let result = template.eval(&vars);
        let expected = r#"Hello Alice,

You have the following notifications:
* Team Meeting at 09:00
* Doctor Appointment at 15:30

Best regards"#;

        assert_eq!(result, expected);
    }

    #[test]
    fn test_complex_template_no_notifications() {
        let template_str = r#"Hello {{name}},

{{#if notifications}}
You have the following notifications:
{{#each notifications}}
* {{name}} at {{time}}
{{/each notifications}}{{/if notifications}}
Best regards"#;

        let template = Template::parse(template_str).unwrap();
        let mut vars = Variables::<String, String>::new();
        vars.insert_single("name".to_string(), "Bob".to_string());

        let result = template.eval(&vars);
        let expected = r#"Hello Bob,


Best regards"#;

        assert_eq!(result, expected);
    }

    #[test]
    fn test_whitespace_handling() {
        let template = Template::parse("{{ name }}").unwrap();
        let mut vars = Variables::<String, String>::new();
        vars.insert_single("name".to_string(), "Test".to_string());

        let result = template.eval(&vars);
        assert_eq!(result, "Test");
    }

    #[test]
    fn test_whitespace_in_blocks() {
        let template = Template::parse("{{# if condition }}Content{{/ if condition }}").unwrap();
        let mut vars = Variables::<String, String>::new();
        vars.insert_single("condition".to_string(), "true".to_string());

        let result = template.eval(&vars);
        assert_eq!(result, "Content");
    }

    // Error handling tests
    #[test]
    fn test_unmatched_opening_brace() {
        let result = Template::<String>::parse("Hello {{name");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unmatched {{"));
    }

    #[test]
    fn test_invalid_block_start() {
        let result = Template::<String>::parse("{{#invalid block}}{{/invalid block}}");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid block start"));
    }

    #[test]
    fn test_invalid_block_end() {
        let result = Template::<String>::parse("{{#if test}}{{\\/invalid block}}");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unmatched"));
    }

    #[test]
    fn test_mismatched_block_names() {
        let result = Template::<String>::parse("{{#if test}}{{/if different}}");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("Block end does not match start")
        );
    }

    #[test]
    fn test_mismatched_block_types() {
        let result = Template::<String>::parse("{{#if test}}{{/each test}}");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("Block end does not match start")
        );
    }

    #[test]
    fn test_consecutive_braces() {
        let template = Template::parse("{{}}").unwrap();
        let vars = Variables::<String, String>::new();

        let result = template.eval(&vars);
        assert_eq!(result, "");
    }

    #[test]
    fn test_foreach_with_missing_inner_variables() {
        let template =
            Template::parse("{{#each items}}{{name}}: {{missing}}{{/each items}}").unwrap();
        let mut vars = Variables::<String, String>::new();

        let items = vec![
            vec![("name".to_string(), "Item1".to_string())],
            vec![("name".to_string(), "Item2".to_string())],
        ];
        vars.insert_block("items".to_string(), items);

        let result = template.eval(&vars);
        assert_eq!(result, "Item1: Item2: ");
    }

    /*#[test]
    fn test_full() {
        // Load static html in memory from resources/email-templates/calendar-alarm.html
        let template_str = include_str!("../../../resources/email-templates/calendar-alarm.html");
        let template: Template<CalendarTemplateVariable> = Template::parse(template_str).unwrap();

        let mut vars = Variables::<CalendarTemplateVariable, String>::new();
        vars.insert_single(
            CalendarTemplateVariable::PageTitle,
            "Test Event".to_string(),
        );
        vars.insert_single(CalendarTemplateVariable::Header, "Event Header".to_string());
        vars.insert_single(CalendarTemplateVariable::Footer, "Event Footer".to_string());
        vars.insert_single(
            CalendarTemplateVariable::EventTitle,
            "Meeting with Team".to_string(),
        );
        vars.insert_single(
            CalendarTemplateVariable::EventDescription,
            "Discuss project updates".to_string(),
        );
        vars.insert_single(
            CalendarTemplateVariable::EventDetails,
            "Details about the event".to_string(),
        );
        vars.insert_single(
            CalendarTemplateVariable::ActionUrl,
            "http://example.com/action".to_string(),
        );
        vars.insert_single(
            CalendarTemplateVariable::ActionName,
            "Join Meeting".to_string(),
        );
        vars.insert_single(
            CalendarTemplateVariable::AttendeesTitle,
            "Attendees".to_string(),
        );
        vars.insert_block(
            CalendarTemplateVariable::EventDetails,
            vec![
                vec![
                    (CalendarTemplateVariable::Key, "Location".to_string()),
                    (
                        CalendarTemplateVariable::Value,
                        "Conference Room A".to_string(),
                    ),
                ],
                vec![
                    (CalendarTemplateVariable::Key, "Time".to_string()),
                    (
                        CalendarTemplateVariable::Value,
                        "10:00 AM - 11:00 AM".to_string(),
                    ),
                ],
            ],
        );
        vars.insert_block(
            CalendarTemplateVariable::Attendees,
            vec![
                vec![
                    (CalendarTemplateVariable::Key, "Alice".to_string()),
                    (
                        CalendarTemplateVariable::Value,
                        "alice@domain.org".to_string(),
                    ),
                ],
                vec![
                    (CalendarTemplateVariable::Key, "Bob".to_string()),
                    (
                        CalendarTemplateVariable::Value,
                        "bob@domain.org".to_string(),
                    ),
                ],
            ],
        );
        let result = template.eval(&vars);
        // Write result to test.html
        std::fs::write("test.html", result).expect("Unable to write file");
    }*/
}
