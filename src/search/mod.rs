//! KeePassXC-compatible structured search query parser and entry filter engine.

use crate::generator::{StrengthLevel, estimate_password};
use crate::model::{Database, Entry};
use regex::RegexBuilder;
use std::collections::HashMap;
use uuid::Uuid;

/// Target field selector for a search predicate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchField {
    /// Default multi-field search (`Title`, `UserName`, `URL`, `Notes`, `Tags`, custom values, group).
    Any,
    /// `title:` / `t:`
    Title,
    /// `user:` / `username:` / `u:`
    Username,
    /// `password:` / `p:`
    Password,
    /// `url:`
    Url,
    /// `notes:` / `n:`
    Notes,
    /// `attr:` / `a:` (matches custom attribute name or value)
    Attribute,
    /// `attach:` (matches attachment filename)
    Attachment,
    /// `group:` / `g:`
    Group,
    /// `tag:` / `tags:`
    Tag,
    /// `uuid:`
    Uuid,
    /// `is:<status>` (`expired`, `weak`, `totp` / `otp`, `reused`, `http`, `attachment`)
    Status,
}

/// Matching mode for a single search term.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchMode {
    /// Case-insensitive substring match (default).
    SubstringInsensitive,
    /// Case-sensitive substring match (`+term`).
    CaseSensitive,
    /// Regular expression match (`*pattern`).
    Regex,
}

/// A single atomic search term (`[-|!][+][*]field:value`).
#[derive(Debug, Clone)]
pub struct SearchTerm {
    /// Whether this term negates its match (`-` or `!`).
    pub negated: bool,
    /// Target field.
    pub field: SearchField,
    /// Comparison mode.
    pub mode: MatchMode,
    /// Pattern string.
    pub pattern: String,
    compiled_regex: Option<regex::Regex>,
}

/// Parsed search query: a disjunction (`|`) of conjunctions (`AND`) of `SearchTerm`s.
#[derive(Debug, Clone, Default)]
pub struct SearchQuery {
    /// OR-branches; each inner `Vec<SearchTerm>` requires all terms to match.
    pub or_clauses: Vec<Vec<SearchTerm>>,
}

/// Precomputed vault-wide context (such as reused password counts) used by `is:reused`.
pub struct SearchContext {
    reused_uuids: Vec<Uuid>,
}

impl SearchContext {
    /// Precomputes reused-password metadata across non-trash entries of `db`.
    #[must_use]
    pub fn from_database(db: &Database) -> Self {
        let mut by_pw: HashMap<&str, Vec<Uuid>> = HashMap::new();
        let all = db.all_entries(false);
        for (_, entry) in &all {
            let pw = entry.password.as_str();
            if !pw.is_empty() {
                by_pw.entry(pw).or_default().push(entry.uuid);
            }
        }
        let mut reused_uuids = Vec::new();
        for uuids in by_pw.values() {
            if uuids.len() > 1 {
                reused_uuids.extend(uuids.iter().copied());
            }
        }
        Self { reused_uuids }
    }
}

impl SearchQuery {
    /// Parses a KeePassXC search string into OR/AND clauses.
    #[must_use]
    pub fn parse(raw: &str) -> Self {
        let tokens = tokenize_query(raw);
        if tokens.is_empty() {
            return Self {
                or_clauses: Vec::new(),
            };
        }

        let mut or_clauses: Vec<Vec<SearchTerm>> = vec![Vec::new()];
        for tok in tokens {
            if tok == "|" || tok.eq_ignore_ascii_case("OR") {
                if !or_clauses.last().is_some_and(Vec::is_empty) {
                    or_clauses.push(Vec::new());
                }
                continue;
            }
            let term = parse_single_term(&tok);
            if let Some(last) = or_clauses.last_mut() {
                last.push(term);
            }
        }
        or_clauses.retain(|c| !c.is_empty());
        Self { or_clauses }
    }

    /// Returns `true` if the query is empty (matches everything).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.or_clauses.is_empty()
    }

    /// Evaluates whether `(group_path, entry)` satisfies the query.
    #[must_use]
    pub fn matches(&self, group_path: &str, entry: &Entry, ctx: &SearchContext) -> bool {
        if self.or_clauses.is_empty() {
            return true;
        }
        self.or_clauses
            .iter()
            .any(|and_terms| and_terms.iter().all(|t| t.matches(group_path, entry, ctx)))
    }
}

impl SearchTerm {
    fn matches(&self, group_path: &str, entry: &Entry, ctx: &SearchContext) -> bool {
        let raw_hit = match self.field {
            SearchField::Status => match self.pattern.to_ascii_lowercase().as_str() {
                "expired" => entry.times.is_expired(),
                "weak" => {
                    !entry.password.is_empty()
                        && estimate_password(entry.password.as_str()).level <= StrengthLevel::Weak
                }
                "totp" | "otp" | "2fa" => {
                    entry.otp.as_ref().is_some_and(|o| !o.is_empty())
                        || entry.get_attribute("TOTP Seed").is_some()
                }
                "reused" | "duplicate" => ctx.reused_uuids.contains(&entry.uuid),
                "http" | "insecure" => entry.url.trim().to_ascii_lowercase().starts_with("http://"),
                "attachment" | "attachments" => !entry.attachments.is_empty(),
                _ => false,
            },
            SearchField::Title => self.text_match(&entry.title),
            SearchField::Username => self.text_match(&entry.username),
            SearchField::Password => self.text_match(entry.password.as_str()),
            SearchField::Url => self.text_match(&entry.url),
            SearchField::Notes => self.text_match(&entry.notes),
            SearchField::Group => self.text_match(group_path),
            SearchField::Uuid => self.text_match(&entry.uuid.to_string()),
            SearchField::Tag => entry.tags.iter().any(|t| self.text_match(t)),
            SearchField::Attachment => entry.attachments.iter().any(|a| self.text_match(&a.name)),
            SearchField::Attribute => entry
                .custom_attributes
                .iter()
                .any(|a| self.text_match(&a.key) || self.text_match(a.value.as_str())),
            SearchField::Any => {
                self.text_match(&entry.title)
                    || self.text_match(&entry.username)
                    || self.text_match(&entry.url)
                    || self.text_match(&entry.notes)
                    || self.text_match(group_path)
                    || entry.tags.iter().any(|t| self.text_match(t))
                    || entry
                        .custom_attributes
                        .iter()
                        .any(|a| !a.protected && self.text_match(a.value.as_str()))
            }
        };

        if self.negated { !raw_hit } else { raw_hit }
    }

    fn text_match(&self, haystack: &str) -> bool {
        match self.mode {
            MatchMode::CaseSensitive => haystack.contains(&self.pattern),
            MatchMode::SubstringInsensitive => haystack
                .to_lowercase()
                .contains(&self.pattern.to_lowercase()),
            MatchMode::Regex => match self.compiled_regex.as_ref() {
                Some(re) => re.is_match(haystack),
                // Pattern failed to compile: fall back to a substring match rather
                // than silently matching nothing (which reads as "0 results").
                None => haystack
                    .to_lowercase()
                    .contains(&self.pattern.to_lowercase()),
            },
        }
    }
}

fn tokenize_query(raw: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut quote_char = '"';

    for ch in raw.chars() {
        if in_quotes {
            if ch == quote_char {
                in_quotes = false;
            } else {
                current.push(ch);
            }
        } else if ch == '"' || ch == '\'' {
            in_quotes = true;
            quote_char = ch;
        } else if ch == '|' && current.is_empty() {
            tokens.push("|".to_string());
        } else if ch.is_whitespace() {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
        } else {
            current.push(ch);
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

fn parse_single_term(raw: &str) -> SearchTerm {
    let mut rest = raw;
    let mut negated = false;
    let mut mode = MatchMode::SubstringInsensitive;

    loop {
        if let Some(s) = rest.strip_prefix('-').or_else(|| rest.strip_prefix('!'))
            && !s.is_empty()
        {
            negated = !negated;
            rest = s;
            continue;
        }
        if let Some(s) = rest.strip_prefix('+')
            && !s.is_empty()
        {
            mode = MatchMode::CaseSensitive;
            rest = s;
            continue;
        }
        if let Some(s) = rest.strip_prefix('*')
            && !s.is_empty()
        {
            mode = MatchMode::Regex;
            rest = s;
            continue;
        }
        break;
    }

    let (field, mut pattern) = if let Some((prefix, rhs)) = rest.split_once(':') {
        let mapped = match prefix.to_ascii_lowercase().as_str() {
            "t" | "title" => Some(SearchField::Title),
            "u" | "user" | "username" => Some(SearchField::Username),
            "p" | "pass" | "password" => Some(SearchField::Password),
            "url" => Some(SearchField::Url),
            "n" | "note" | "notes" => Some(SearchField::Notes),
            "a" | "attr" | "attribute" => Some(SearchField::Attribute),
            "attach" | "attachment" => Some(SearchField::Attachment),
            "g" | "group" => Some(SearchField::Group),
            "tag" | "tags" => Some(SearchField::Tag),
            "uuid" | "id" => Some(SearchField::Uuid),
            "is" | "has" => Some(SearchField::Status),
            _ => None,
        };
        match mapped {
            Some(f) => (f, rhs.to_string()),
            None => (SearchField::Any, rest.to_string()),
        }
    } else {
        (SearchField::Any, rest.to_string())
    };

    if let Some(stripped) = pattern.strip_prefix('*')
        && !stripped.is_empty()
    {
        mode = MatchMode::Regex;
        pattern = stripped.to_string();
    } else if let Some(stripped) = pattern.strip_prefix('+')
        && !stripped.is_empty()
    {
        mode = MatchMode::CaseSensitive;
        pattern = stripped.to_string();
    }

    let compiled_regex = if mode == MatchMode::Regex {
        RegexBuilder::new(&pattern)
            .case_insensitive(true)
            .build()
            .ok()
    } else {
        None
    };

    SearchTerm {
        negated,
        field,
        mode,
        pattern,
        compiled_regex,
    }
}

/// Searches `db` using `query_str` (excluding the Recycle Bin unless `include_recycle_bin` is `true`)
/// and returns matching `(full_entry_path, &Entry)` pairs.
#[must_use]
pub fn search_database<'a>(
    db: &'a Database,
    query_str: &str,
    include_recycle_bin: bool,
) -> Vec<(String, &'a Entry)> {
    let query = SearchQuery::parse(query_str);
    let ctx = SearchContext::from_database(db);
    let mut results = Vec::new();
    walk_searchable(
        db,
        &db.root,
        "",
        false,
        false,
        include_recycle_bin,
        &query,
        &ctx,
        &mut results,
    );
    results
}

/// Single-pass searchable traversal.
///
/// Honors `enable_searching = Some(false)` inherited from parent groups (including on
/// root-level entries), and only descends into the Recycle Bin when explicitly asked —
/// an explicit trash search overrides the bin's own searching opt-out.
#[allow(clippy::too_many_arguments)]
fn walk_searchable<'a>(
    db: &Database,
    group: &'a crate::model::Group,
    path: &str,
    in_bin: bool,
    opted_out: bool,
    include_bin: bool,
    query: &SearchQuery,
    ctx: &SearchContext,
    out: &mut Vec<(String, &'a Entry)>,
) {
    let is_bin = in_bin || group.uuid == db.meta.recycle_bin_uuid;
    let opted_out = opted_out || group.enable_searching == Some(false);
    if is_bin && !include_bin {
        return;
    }
    if opted_out && !(is_bin && include_bin) {
        return;
    }
    for entry in &group.entries {
        if query.matches(path, entry, ctx) {
            let full_path = if path.is_empty() {
                format!("/{}", entry.title)
            } else {
                format!("/{path}/{}", entry.title)
            };
            out.push((full_path, entry));
        }
    }
    for child in &group.children {
        let child_path = if path.is_empty() {
            child.name.clone()
        } else {
            format!("{path}/{}", child.name)
        };
        walk_searchable(
            db,
            child,
            &child_path,
            is_bin,
            opted_out,
            include_bin,
            query,
            ctx,
            out,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Database;

    #[test]
    fn structured_modifiers_and_status_filters_match() {
        let mut db = Database::new("Vault");
        let mut e1 = Entry::new("GitHub");
        e1.username = "alice".to_string();
        e1.password = "weak".into();
        e1.url = "https://github.com".to_string();
        e1.otp = Some("otpauth://totp/GitHub?secret=JBSWY3DPEHPK3PXP".into());
        db.add_entry_at_path("Dev/GitHub", e1).expect("add");

        let mut e2 = Entry::new("Router");
        e2.username = "admin".to_string();
        e2.password = "weak".into();
        e2.url = "http://192.168.1.1".to_string();
        db.add_entry_at_path("Infra/Router", e2).expect("add");

        assert_eq!(search_database(&db, "u:alice is:totp", false).len(), 1);
        assert_eq!(search_database(&db, "is:http", false).len(), 1);
        assert_eq!(search_database(&db, "is:reused", false).len(), 2);
        assert_eq!(search_database(&db, "is:reused -g:Infra", false).len(), 1);
        assert_eq!(search_database(&db, "t:GitHub | t:Router", false).len(), 2);
    }
}

#[cfg(test)]
mod recycle_bin_and_optout_tests {
    use super::*;
    use crate::model::Entry;

    #[test]
    fn explicit_recycle_bin_search_overrides_the_bin_optout() {
        let mut db = Database::new("V");
        db.add_entry_at_path("Keep/Real", Entry::new("Real"))
            .expect("add");
        let trashed_uuid = {
            db.add_entry_at_path("Keep/Trashed", Entry::new("Trashed"))
                .expect("add")
        };
        db.delete_entry_by_uuid(trashed_uuid, false).expect("trash");
        // The bin exists and opted out of searching…
        assert!(!db.meta.recycle_bin_uuid.is_nil());
        // …so default search excludes it…
        assert_eq!(search_database(&db, "t:Trashed", false).len(), 0);
        assert_eq!(search_database(&db, "t:Real", false).len(), 1);
        // …but an explicit trash search must return it.
        assert_eq!(search_database(&db, "t:Trashed", true).len(), 1);
    }

    #[test]
    fn root_level_entries_honor_root_searching_optout() {
        let mut db = Database::new("V");
        let mut e = Entry::new("RootSecret");
        e.username = "u".to_string();
        db.root.entries.push(e);
        db.root.enable_searching = Some(false);
        assert_eq!(search_database(&db, "u:u", false).len(), 0);
        db.root.enable_searching = Some(true);
        assert_eq!(search_database(&db, "u:u", false).len(), 1);
    }

    #[test]
    fn parent_group_optout_excludes_whole_subtree() {
        let mut db = Database::new("V");
        db.add_entry_at_path("Hidden/One", Entry::new("One"))
            .expect("add");
        if let Ok(g) = db.resolve_group_mut("Hidden") {
            g.enable_searching = Some(false);
        }
        assert_eq!(search_database(&db, "t:One", false).len(), 0);
    }
}
