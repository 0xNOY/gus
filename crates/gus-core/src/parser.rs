use std::ffi::{OsStr, OsString};

use crate::model::{
    ConfigEnvOverride, ConfigOverride, GlobalOptions, InvocationContext, NormalizedInvocation,
    Operation, ParseIssue,
};

pub(crate) fn parse<I, S>(args: I) -> InvocationContext
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let raw_args: Vec<OsString> = args
        .into_iter()
        .map(|argument| argument.as_ref().to_owned())
        .collect();
    InvocationContext::from_normalized(normalize(raw_args))
}

fn normalize(raw_args: Vec<OsString>) -> NormalizedInvocation {
    let mut global = GlobalOptions::default();
    let mut index = 0;
    let mut issue = None;

    while index < raw_args.len() {
        let Some(arg) = raw_args[index].to_str() else {
            issue = Some(ParseIssue::InvalidEncoding);
            break;
        };
        if !arg.starts_with('-') || arg == "-" {
            break;
        }

        match arg {
            "-C" => match take_value(&raw_args, &mut index) {
                Some(value) if !value.is_empty() => global.directory_changes.push(value.to_owned()),
                Some(_) => issue = Some(ParseIssue::MalformedOptionValue),
                None => issue = Some(ParseIssue::MissingOptionValue),
            },
            "--git-dir" => match take_value(&raw_args, &mut index) {
                Some(value) if !value.is_empty() => global.git_dir = Some(value.to_owned()),
                Some(_) => issue = Some(ParseIssue::MalformedOptionValue),
                None => issue = Some(ParseIssue::MissingOptionValue),
            },
            "--work-tree" => match take_value(&raw_args, &mut index) {
                Some(value) if !value.is_empty() => global.work_tree = Some(value.to_owned()),
                Some(_) => issue = Some(ParseIssue::MalformedOptionValue),
                None => issue = Some(ParseIssue::MissingOptionValue),
            },
            "-c" => match take_value(&raw_args, &mut index) {
                Some(value) => match parse_config_override(value) {
                    Some(value) => global.config_overrides.push(value),
                    None => issue = Some(ParseIssue::MalformedOptionValue),
                },
                None => issue = Some(ParseIssue::MissingOptionValue),
            },
            "--config-env" => match take_value(&raw_args, &mut index) {
                Some(value) => match parse_config_env(value) {
                    Some(value) => global.config_env_overrides.push(value),
                    None => issue = Some(ParseIssue::MalformedOptionValue),
                },
                None => issue = Some(ParseIssue::MissingOptionValue),
            },
            _ if arg.starts_with("--git-dir=") => {
                parse_attached_path(arg, "--git-dir=").map_or_else(
                    || issue = Some(ParseIssue::MalformedOptionValue),
                    |value| global.git_dir = Some(value),
                );
            }
            _ if arg.starts_with("--work-tree=") => {
                parse_attached_path(arg, "--work-tree=").map_or_else(
                    || issue = Some(ParseIssue::MalformedOptionValue),
                    |value| global.work_tree = Some(value),
                );
            }
            _ if arg.starts_with("--config-env=") => {
                match parse_config_env(OsStr::new(&arg["--config-env=".len()..])) {
                    Some(value) => global.config_env_overrides.push(value),
                    None => issue = Some(ParseIssue::MalformedOptionValue),
                }
            }
            "--no-pager"
            | "--paginate"
            | "-p"
            | "-P"
            | "--bare"
            | "--no-replace-objects"
            | "--literal-pathspecs"
            | "--glob-pathspecs"
            | "--noglob-pathspecs"
            | "--icase-pathspecs" => global.flags.push(arg.to_owned()),
            _ => issue = Some(ParseIssue::UnknownGlobalOption),
        }

        if issue.is_some() {
            break;
        }
        index += 1;
    }

    finish_normalization(raw_args, global, index, issue)
}

fn finish_normalization(
    raw_args: Vec<OsString>,
    global: GlobalOptions,
    index: usize,
    issue: Option<ParseIssue>,
) -> NormalizedInvocation {
    if let Some(issue) = issue {
        return failed_invocation(raw_args, global, issue);
    }

    let Some(command_os) = raw_args.get(index) else {
        return failed_invocation(raw_args, global, ParseIssue::EmptyInvocation);
    };
    let Some(command) = command_os.to_str().map(str::to_owned) else {
        return failed_invocation(raw_args, global, ParseIssue::InvalidEncoding);
    };
    let command_args = raw_args[index + 1..].to_vec();
    let operation = classify_operation(&command, &command_args);

    NormalizedInvocation {
        raw_args,
        global,
        command: Some(command),
        command_args,
        operation,
        issue: None,
    }
}

fn failed_invocation(
    raw_args: Vec<OsString>,
    global: GlobalOptions,
    issue: ParseIssue,
) -> NormalizedInvocation {
    NormalizedInvocation {
        raw_args,
        global,
        command: None,
        command_args: Vec::new(),
        operation: Operation::Unknown,
        issue: Some(issue),
    }
}

fn take_value<'a>(args: &'a [OsString], index: &mut usize) -> Option<&'a OsStr> {
    *index += 1;
    args.get(*index).map(OsString::as_os_str)
}

fn parse_attached_path(value: &str, prefix: &str) -> Option<OsString> {
    let value = &value[prefix.len()..];
    (!value.is_empty()).then(|| OsString::from(value))
}

fn parse_config_override(value: &OsStr) -> Option<ConfigOverride> {
    let value = value.to_str()?;
    let (name, value) = value.split_once('=')?;
    if !valid_config_name(name) {
        return None;
    }
    Some(ConfigOverride {
        name: name.to_owned(),
        value: value.into(),
    })
}

fn parse_config_env(value: &OsStr) -> Option<ConfigEnvOverride> {
    let value = value.to_str()?;
    let (name, environment_variable) = value.split_once('=')?;
    if !valid_config_name(name) || !valid_environment_variable(environment_variable) {
        return None;
    }
    Some(ConfigEnvOverride {
        name: name.to_owned(),
        environment_variable: environment_variable.to_owned(),
    })
}

fn valid_config_name(name: &str) -> bool {
    !name.is_empty()
        && name.contains('.')
        && !name.chars().any(char::is_whitespace)
        && !name.starts_with('.')
        && !name.ends_with('.')
}

fn valid_environment_variable(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some('_' | 'A'..='Z' | 'a'..='z'))
        && chars.all(|character| matches!(character, '_' | 'A'..='Z' | 'a'..='z' | '0'..='9'))
}

fn classify_operation(command: &str, args: &[OsString]) -> Operation {
    match command {
        "status" | "diff" | "log" | "show" | "blame" | "rev-parse" | "rev-list" | "ls-files"
        | "cat-file" => Operation::ReadOnly,
        "add" | "restore" | "checkout" | "switch" => Operation::WorkingTree,
        "config" => classify_config(args),
        "fetch" => Operation::Fetch,
        "clone" => Operation::Clone,
        "ls-remote" => Operation::LsRemote,
        "pull" => Operation::Pull {
            ff_only_candidate: pull_ff_only_is_candidate(args),
        },
        "push" => Operation::Push,
        "commit" => Operation::Commit,
        "commit-tree" => Operation::CommitTree,
        "merge" => Operation::Merge {
            ff_only_candidate: merge_ff_only_is_candidate(args),
        },
        "rebase" | "cherry-pick" | "revert" | "am" => Operation::HistoryRewrite,
        "stash" => Operation::Stash,
        "tag" => classify_tag(args),
        _ => Operation::Unknown,
    }
}

fn classify_config(args: &[OsString]) -> Operation {
    const READ_ACTIONS: &[&str] = &[
        "--get",
        "--get-all",
        "--get-regexp",
        "--get-urlmatch",
        "--list",
        "-l",
    ];
    const READ_MODIFIERS: &[&str] = &[
        "--show-origin",
        "--show-scope",
        "--name-only",
        "--null",
        "-z",
    ];

    let has_read_action = args
        .iter()
        .any(|arg| arg.to_str().is_some_and(|arg| READ_ACTIONS.contains(&arg)));
    let contains_unknown_option = args.iter().any(|arg| {
        let Some(arg) = arg.to_str() else {
            return true;
        };
        arg.starts_with('-') && !READ_ACTIONS.contains(&arg) && !READ_MODIFIERS.contains(&arg)
    });

    if has_read_action && !contains_unknown_option {
        Operation::ConfigRead
    } else {
        Operation::ConfigWriteOrUnknown
    }
}

fn pull_ff_only_is_candidate(args: &[OsString]) -> bool {
    let mut found = false;
    for arg in args {
        let Some(arg) = arg.to_str() else {
            return false;
        };
        match arg {
            "--ff-only" => found = true,
            "--autostash" | "--rebase" | "-r" => return false,
            "-q"
            | "--quiet"
            | "-v"
            | "--verbose"
            | "--progress"
            | "--no-progress"
            | "--tags"
            | "--no-tags"
            | "--prune"
            | "--no-prune"
            | "--dry-run"
            | "-f"
            | "--force"
            | "--update-shallow"
            | "--no-update-shallow"
            | "--show-forced-updates"
            | "--no-show-forced-updates"
            | "--stat"
            | "--no-stat"
            | "--compact-summary"
            | "--no-compact-summary"
            | "--" => {}
            value if !value.starts_with('-') => {}
            _ => return false,
        }
    }
    found
}

fn merge_ff_only_is_candidate(args: &[OsString]) -> bool {
    let mut found_ff_only = false;
    let mut found_head = false;
    let mut after_separator = false;

    for argument in args {
        if after_separator {
            found_head = true;
            continue;
        }
        let Some(argument) = argument.to_str() else {
            return false;
        };
        match argument {
            "--ff-only" => found_ff_only = true,
            "--" => after_separator = true,
            "-q"
            | "--quiet"
            | "-v"
            | "--verbose"
            | "--progress"
            | "--no-progress"
            | "--stat"
            | "-n"
            | "--no-stat"
            | "--compact-summary"
            | "--no-compact-summary" => {}
            value if !value.starts_with('-') => found_head = true,
            _ => return false,
        }
    }

    found_ff_only && found_head
}

fn classify_tag(args: &[OsString]) -> Operation {
    if args.is_empty() || args.iter().any(|arg| matches_ascii(arg, &["-l", "--list"])) {
        return Operation::ReadOnly;
    }
    if args
        .iter()
        .any(|arg| matches_ascii(arg, &["-s", "--sign", "-u", "--local-user"]))
    {
        return Operation::SignedTag;
    }
    if args.iter().any(|arg| {
        matches_ascii(
            arg,
            &["-a", "--annotate", "-m", "--message", "-F", "--file"],
        )
    }) {
        return Operation::AnnotatedTag;
    }
    if args
        .iter()
        .any(|arg| arg.to_str().is_none_or(|arg| arg.starts_with('-')))
    {
        return Operation::Unknown;
    }
    Operation::LightweightTagCandidate
}

fn matches_ascii(argument: &OsStr, values: &[&str]) -> bool {
    argument
        .to_str()
        .is_some_and(|argument| values.contains(&argument))
}
