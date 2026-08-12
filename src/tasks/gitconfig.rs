//! Editing a git configuration file without losing what is already in it.
//!
//! `git config` would do this, and is not used, for the reason every other
//! write in this project avoids shelling out to the program that owns the file:
//! the value would have to reach a shell. A name carrying an apostrophe is
//! ordinary, and quoting one correctly through `runuser -c` is the kind of
//! thing that works until somebody is called O'Brien.
//!
//! So the file is parsed here instead — and "parsed" is generous. This
//! understands exactly the subset it writes: section headers, `key = value`
//! lines, and comments. It does *not* understand includes, conditional
//! includes, subsections or line continuations, and it does not need to: it
//! only ever replaces a key it recognises inside a section it recognises, and
//! leaves every other line exactly as it found it.
//!
//! That last property is the one that matters. An operator's `~/.gitconfig` is
//! theirs, and a tool that rewrote it into its own idea of tidy would be
//! destroying work while reporting success.

/// The section and key an identity's name lives under.
const USER_SECTION: &str = "user";
const NAME_KEY: &str = "name";
const EMAIL_KEY: &str = "email";

/// Where `init.defaultBranch` lives.
const INIT_SECTION: &str = "init";
const DEFAULT_BRANCH_KEY: &str = "defaultBranch";

/// Where `safe.directory` lives.
const SAFE_SECTION: &str = "safe";
const DIRECTORY_KEY: &str = "directory";

/// Returns the file with `user.name` and `user.email` set to these values.
pub fn with_identity(existing: &str, name: &str, email: &str) -> String {
    let with_name = with_setting(existing, USER_SECTION, NAME_KEY, name);

    with_setting(&with_name, USER_SECTION, EMAIL_KEY, email)
}

/// Returns the file with `init.defaultBranch` set to this branch.
pub fn with_default_branch(existing: &str, branch: &str) -> String {
    with_setting(existing, INIT_SECTION, DEFAULT_BRANCH_KEY, branch)
}

/// Returns the file with this path added to `safe.directory`.
///
/// Added rather than replaced, which is the one place this module differs from
/// the others: `safe.directory` is a multi-valued key, and a host with three
/// deploy checkouts needs three entries. Replacing would silently un-trust the
/// other two — and the failure would surface later, somewhere else, as git
/// refusing to read a repository it read yesterday.
pub fn with_safe_directory(existing: &str, path: &str) -> String {
    if safe_directories(existing).any(|entry| entry == path) {
        return existing.to_owned();
    }

    append_to_section(existing, SAFE_SECTION, DIRECTORY_KEY, path)
}

/// Every path currently trusted, in the order the file lists them.
pub fn safe_directories(contents: &str) -> impl Iterator<Item = &str> {
    values_of(contents, SAFE_SECTION, DIRECTORY_KEY)
}

/// The value of a single-valued key, if the file sets one.
///
/// Not called outside the tests today, and kept because the tests are what it
/// is for: asserting on the file's *meaning* rather than on its text. A test
/// checking `contains("name = Ada")` passes against a file where a later line
/// overrides it, which is exactly the bug worth catching.
#[cfg_attr(not(test), allow(dead_code))]
pub fn value_of<'a>(contents: &'a str, section: &str, key: &str) -> Option<&'a str> {
    values_of(contents, section, key).next_back()
}

/// Every value a key is given, in file order.
///
/// Plural because git's own semantics are: the last wins for a single-valued
/// key, and all of them count for a multi-valued one. Reading only the first
/// would disagree with git about a file git accepts.
fn values_of<'a>(
    contents: &'a str,
    section: &str,
    key: &str,
) -> std::iter::Rev<std::vec::IntoIter<&'a str>> {
    let mut found = Vec::new();
    let mut current = String::new();

    for line in contents.lines() {
        if let Some(name) = section_header(line) {
            current = name;
            continue;
        }

        if current != section {
            continue;
        }

        if let Some((found_key, value)) = setting(line)
            && found_key.eq_ignore_ascii_case(key)
        {
            found.push(value);
        }
    }

    found.reverse();
    found.into_iter().rev()
}

/// The section a header line opens, if it is one.
///
/// `[user]` and `[ user ]` both open `user`. A subsection — `[includeIf
/// "gitdir:~/work/"]` — is deliberately *not* matched as its parent: treating
/// it as one would let a key be written under a condition that does not hold.
fn section_header(line: &str) -> Option<String> {
    let trimmed = line.trim();
    let inner = trimmed.strip_prefix('[')?.strip_suffix(']')?.trim();

    if inner.contains('"') || inner.is_empty() {
        return None;
    }

    Some(inner.to_ascii_lowercase())
}

/// The key and value a setting line carries, if it is one.
fn setting(line: &str) -> Option<(&str, &str)> {
    let trimmed = line.trim();

    // Both comment characters git accepts. A commented-out setting is not one.
    if trimmed.starts_with('#') || trimmed.starts_with(';') || trimmed.is_empty() {
        return None;
    }

    let (key, value) = trimmed.split_once('=')?;

    Some((key.trim(), value.trim()))
}

/// Replaces a key's value, or adds the key, or adds the section and the key.
fn with_setting(existing: &str, section: &str, key: &str, value: &str) -> String {
    let mut lines: Vec<String> = existing.lines().map(str::to_owned).collect();
    let mut current = String::new();
    let mut replaced = false;
    let mut section_ends_at = None;

    for (index, line) in lines.clone().iter().enumerate() {
        if let Some(name) = section_header(line) {
            // Leaving the section without having found the key: remember where
            // it ended, so the key can be added inside it rather than at the
            // bottom of the file under whatever section happens to be last.
            if current == section && section_ends_at.is_none() {
                section_ends_at = Some(index);
            }

            current = name;
            continue;
        }

        if current != section {
            continue;
        }

        if let Some((found_key, _)) = setting(&lines[index])
            && found_key.eq_ignore_ascii_case(key)
        {
            lines[index] = format!("\t{key} = {value}");
            replaced = true;
        }
    }

    if replaced {
        return rejoin(&lines);
    }

    match section_ends_at.or_else(|| current.eq(section).then_some(lines.len())) {
        // The section exists: the key goes at its end.
        Some(at) => lines.insert(at, format!("\t{key} = {value}")),
        // It does not: both are appended.
        None => {
            if !lines.is_empty() {
                lines.push(String::new());
            }
            lines.push(format!("[{section}]"));
            lines.push(format!("\t{key} = {value}"));
        }
    }

    rejoin(&lines)
}

/// Adds another value for a key that may already have several.
fn append_to_section(existing: &str, section: &str, key: &str, value: &str) -> String {
    let mut lines: Vec<String> = existing.lines().map(str::to_owned).collect();
    let mut current = String::new();
    let mut section_ends_at = None;

    for (index, line) in lines.iter().enumerate() {
        if let Some(name) = section_header(line) {
            if current == section && section_ends_at.is_none() {
                section_ends_at = Some(index);
            }

            current = name;
        }
    }

    match section_ends_at.or_else(|| current.eq(section).then_some(lines.len())) {
        Some(at) => lines.insert(at, format!("\t{key} = {value}")),
        None => {
            if !lines.is_empty() {
                lines.push(String::new());
            }
            lines.push(format!("[{section}]"));
            lines.push(format!("\t{key} = {value}"));
        }
    }

    rejoin(&lines)
}

/// Reassembles the lines, always ending the file with a newline.
///
/// Unconditionally, which is a decision rather than an oversight. Keeping the
/// file exactly as found would mean a file that arrived without a final newline
/// keeps having none — and the next tool to append to it, `git config`
/// included, joins its new section onto the last line. `git config` itself
/// always writes one, so this agrees with the program that owns the file rather
/// than preserving a state that program would have fixed.
fn rejoin(lines: &[String]) -> String {
    let mut joined = lines.join("\n");

    if !joined.ends_with('\n') {
        joined.push('\n');
    }

    joined
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_identity_is_written_into_an_empty_file() {
        let written = with_identity("", "Ada Lovelace", "ada@example.com");

        assert!(written.contains("[user]"), "{written}");
        assert!(written.contains("name = Ada Lovelace"), "{written}");
        assert!(written.contains("email = ada@example.com"), "{written}");
    }

    #[test]
    fn an_existing_identity_is_replaced_rather_than_duplicated() {
        // Two `user.name` lines is a file git reads by taking the last, so a
        // duplicate is not wrong so much as untraceable: the operator sees the
        // old value and the new one and cannot tell which is in effect.
        let before = "[user]\n\tname = Old Name\n\temail = old@example.com\n";

        let after = with_identity(before, "Ada Lovelace", "ada@example.com");

        // Once for `name` and once inside `email`, which is what makes
        // counting the wrong check on its own — the assertion below is the one
        // that means something.
        assert_eq!(after.matches("name = ").count(), 1, "{after}");
        assert!(!after.contains("Old Name"), "{after}");
        assert_eq!(
            value_of(&after, "user", "name"),
            Some("Ada Lovelace"),
            "{after}"
        );
    }

    #[test]
    fn everything_the_operator_wrote_survives() {
        // The property this module exists for. A tool that tidied somebody's
        // config into its own shape would be destroying work while reporting
        // success.
        let before = "# my config\n\
                      [alias]\n\
                      \tlg = log --graph\n\
                      [user]\n\
                      \tname = Old\n\
                      [core]\n\
                      \teditor = vim\n";

        let after = with_identity(before, "Ada", "ada@example.com");

        assert!(after.contains("# my config"), "{after}");
        assert!(after.contains("lg = log --graph"), "{after}");
        assert!(after.contains("editor = vim"), "{after}");
    }

    #[test]
    fn a_key_lands_in_its_own_section_rather_than_at_the_end() {
        // Appending to the bottom of the file would put `email` under `[core]`,
        // where git reads it as `core.email` and nothing has an identity.
        let before = "[user]\n\tname = Ada\n[core]\n\teditor = vim\n";

        let after = with_identity(before, "Ada", "ada@example.com");

        let email_at = after.find("email =").expect("email must be written");
        let core_at = after.find("[core]").expect("core must survive");

        assert!(email_at < core_at, "{after}");
    }

    #[test]
    fn a_second_safe_directory_does_not_replace_the_first() {
        // Multi-valued, unlike everything else here. Replacing would un-trust a
        // checkout that worked yesterday, and the failure would surface
        // somewhere else entirely.
        let first = with_safe_directory("", "/srv/one");
        let both = with_safe_directory(&first, "/srv/two");

        let trusted: Vec<&str> = safe_directories(&both).collect();

        assert_eq!(trusted, vec!["/srv/one", "/srv/two"], "{both}");
    }

    #[test]
    fn trusting_the_same_directory_twice_changes_nothing() {
        let once = with_safe_directory("", "/srv/one");
        let twice = with_safe_directory(&once, "/srv/one");

        assert_eq!(once, twice);
    }

    #[test]
    fn a_commented_setting_is_not_a_setting() {
        // Both of git's comment characters. Treating `# name = X` as a value
        // would have this replace a line the operator deliberately disabled.
        let before = "[user]\n\t# name = Disabled\n\t; email = Also disabled\n";

        let after = with_identity(before, "Ada", "ada@example.com");

        assert!(after.contains("# name = Disabled"), "{after}");
        assert!(after.contains("; email = Also disabled"), "{after}");
        assert_eq!(value_of(&after, "user", "name"), Some("Ada"), "{after}");
    }

    #[test]
    fn a_conditional_include_is_not_the_section_it_resembles() {
        // `[includeIf "gitdir:~/work/"]` is a subsection, and a key written
        // into it applies only where the condition holds. Matching it as
        // `[user]` would write an identity that silently does not apply.
        let before = "[includeIf \"gitdir:~/work/\"]\n\tpath = ~/.gitconfig-work\n";

        let after = with_identity(before, "Ada", "ada@example.com");

        assert!(after.contains("[user]"), "{after}");
        assert!(after.contains("path = ~/.gitconfig-work"), "{after}");
    }

    #[test]
    fn section_names_are_matched_without_regard_to_case() {
        // git treats `[USER]` and `[user]` as one section, so a second `[user]`
        // written beside an existing `[USER]` would split an identity across
        // two headers.
        let before = "[USER]\n\tname = Ada\n";

        let after = with_identity(before, "Ada Lovelace", "ada@example.com");

        assert_eq!(after.matches("[USER]").count(), 1, "{after}");
        assert!(!after.contains("[user]"), "{after}");
    }

    #[test]
    fn a_file_without_a_trailing_newline_gets_one() {
        let after = with_default_branch("[init]\n\tdefaultBranch = master", "main");

        assert!(after.ends_with('\n'), "{after:?}");
        assert_eq!(value_of(&after, "init", "defaultBranch"), Some("main"));
    }

    #[test]
    fn the_last_value_wins_as_git_reads_it() {
        // A file git accepts and this must agree with: for a single-valued key
        // the last assignment is the effective one.
        let contents = "[init]\n\tdefaultBranch = first\n\tdefaultBranch = second\n";

        assert_eq!(value_of(contents, "init", "defaultBranch"), Some("second"));
    }
}
