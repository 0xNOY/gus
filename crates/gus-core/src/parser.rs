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
    if is_global_information_request(&raw_args) {
        return global_information(raw_args);
    }

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
            "--namespace" => match take_value(&raw_args, &mut index) {
                Some(value) if !value.is_empty() => global.namespace = Some(value.to_owned()),
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
            _ if arg.starts_with("--namespace=") => {
                parse_attached_path(arg, "--namespace=").map_or_else(
                    || issue = Some(ParseIssue::MalformedOptionValue),
                    |value| global.namespace = Some(value),
                );
            }
            _ if arg.starts_with("--exec-path=") => {
                parse_attached_path(arg, "--exec-path=").map_or_else(
                    || issue = Some(ParseIssue::MalformedOptionValue),
                    |value| global.exec_path = Some(value),
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
            | "--no-optional-locks"
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

fn global_information(raw_args: Vec<OsString>) -> NormalizedInvocation {
    let command = raw_args[0]
        .to_str()
        .expect("information requests are ASCII")
        .to_owned();
    NormalizedInvocation {
        raw_args,
        global: GlobalOptions::default(),
        command: Some(command),
        command_args: Vec::new(),
        operation: Operation::Informational,
        issue: None,
    }
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
        "version" if version_is_informational(args) => Operation::Informational,
        "help" => Operation::Informational,
        "status" | "diff" | "log" | "show" | "blame" | "rev-parse" | "rev-list" | "ls-files"
        | "cat-file" | "for-each-ref" | "show-ref" | "merge-base" | "name-rev" | "check-ignore"
        | "check-attr" | "count-objects" => Operation::ReadOnly,
        "symbolic-ref" => classify_symbolic_ref(args),
        "remote" => classify_remote(args),
        "branch" => classify_branch(args),
        "add" | "restore" | "checkout" | "switch" | "init" | "reset" | "clean" | "rm" | "mv"
        | "update-index" => Operation::WorkingTree,
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
        "stash" => classify_stash(args),
        "tag" => classify_tag(args),
        _ => Operation::Unknown,
    }
}

fn is_global_information_request(args: &[OsString]) -> bool {
    matches!(
        args,
        [argument]
            if matches_ascii(
                argument,
                &[
                    "-h",
                    "--help",
                    "--version",
                    "--exec-path",
                    "--html-path",
                    "--man-path",
                    "--info-path",
                ]
            )
    )
}

fn version_is_informational(args: &[OsString]) -> bool {
    args.is_empty() || matches!(args, [argument] if argument == "--build-options")
}

fn classify_symbolic_ref(args: &[OsString]) -> Operation {
    let mut names = 0;
    for argument in args {
        let Some(argument) = argument.to_str() else {
            return Operation::Unknown;
        };
        match argument {
            "-q" | "--quiet" | "--short" | "--no-recurse" => {}
            "-m" => return Operation::WorkingTree,
            value if !value.starts_with('-') => names += 1,
            _ => return Operation::Unknown,
        }
    }
    if names == 1 {
        Operation::ReadOnly
    } else if names == 2 {
        Operation::WorkingTree
    } else {
        Operation::Unknown
    }
}

fn classify_remote(args: &[OsString]) -> Operation {
    match args {
        [] => Operation::ReadOnly,
        [flag] if matches_ascii(flag, &["-v", "--verbose"]) => Operation::ReadOnly,
        [action, ..]
            if matches_ascii(
                action,
                &[
                    "add",
                    "rename",
                    "remove",
                    "set-head",
                    "set-branches",
                    "set-url",
                ],
            ) =>
        {
            Operation::WorkingTree
        }
        _ => Operation::Unknown,
    }
}

fn classify_branch(args: &[OsString]) -> Operation {
    const READ_FLAGS: &[&str] = &[
        "--list",
        "-l",
        "--show-current",
        "-a",
        "--all",
        "-r",
        "--remotes",
        "-v",
        "-vv",
        "--verbose",
        "--no-color",
        "--ignore-case",
        "--omit-empty",
    ];
    const MUTATION_FLAGS: &[&str] = &[
        "-d",
        "-D",
        "--delete",
        "-m",
        "-M",
        "--move",
        "-c",
        "-C",
        "--copy",
        "--set-upstream-to",
        "--unset-upstream",
        "--edit-description",
    ];
    if args.is_empty() {
        return Operation::ReadOnly;
    }
    let mut read_only = true;
    for argument in args {
        let Some(argument) = argument.to_str() else {
            return Operation::Unknown;
        };
        if MUTATION_FLAGS.contains(&argument) || !argument.starts_with('-') {
            read_only = false;
        } else if !READ_FLAGS.contains(&argument) {
            return Operation::Unknown;
        }
    }
    if read_only {
        Operation::ReadOnly
    } else {
        Operation::WorkingTree
    }
}

fn classify_stash(args: &[OsString]) -> Operation {
    match args {
        [action, ..] if matches_ascii(action, &["list", "show"]) => Operation::ReadOnly,
        _ => Operation::Stash,
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
            "--no-autostash"
            | "--no-rebase"
            | "-q"
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
            "--no-autostash"
            | "-q"
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
