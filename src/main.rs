//! `initd` — multi-distro Linux server administration TUI.
//!
//! With no arguments it starts the TUI; with a subcommand it runs that action
//! from the CLI.

mod backend;
mod distro;
mod domain;
mod error;
mod exec;
mod i18n;
mod tasks;
mod tui;

pub use error::{Error, Result};

use crate::tasks::params::ParamValues;

fn main() {
    // Errors are rendered through the i18n catalogue rather than printed with
    // `Debug`, and turned into an exit code here so `run` stays pure.
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

/// Dispatches to the TUI or a CLI subcommand.
///
/// Argument parsing stays hand-rolled: the subcommand surface is small and a
/// parser crate would be one more dependency to audit for little gain.
fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    match args.first().map(String::as_str) {
        // Accepted in both spellings because both are habits: `initd version`
        // matches the other subcommands, and `--version` is what anyone tries
        // first on a binary they were handed.
        Some("version" | "--version" | "-V") => {
            cmd_version();
            Ok(())
        }
        Some("detect") => cmd_detect(),
        Some("privileges") => cmd_privileges(),
        Some("list") => cmd_list(),
        // The task id is `args[1]`; the values start after it. Slicing from 1
        // would hand the id back as a value and every task would report its own
        // name as a malformed pair.
        Some("run") => cmd_run(args.get(1).map(String::as_str), &args[2.min(args.len())..]),
        Some("authorize-key") => cmd_authorize_key(&args[1..]),
        Some("change-port") => cmd_change_port(args.get(1).map(String::as_str)),
        Some(other) => {
            eprintln!("unknown subcommand: {other}");
            usage();
            std::process::exit(2);
        }
        // No arguments starts the interactive interface.
        None => tui::run(),
    }
}

/// Prints which build this is.
///
/// On stdout rather than stderr: a version is an answer to a question that was
/// asked, not a diagnostic, and it is the first thing a bug report needs — a
/// report against a binary nobody can identify cannot be acted on.
fn cmd_version() {
    println!("initd {}", env!("CARGO_PKG_VERSION"));
}

/// Prints the available subcommands.
fn usage() {
    eprintln!("usage: initd <command>");
    eprintln!();
    eprintln!("  version                      show which build this is");
    eprintln!("  detect                       show the detected distribution");
    eprintln!("  privileges                   show the privilege escalation mechanism");
    eprintln!("  list                         list the available tasks");
    eprintln!("  run <task-id> [name=value]   run a task, supplying what it needs");
    eprintln!("  authorize-key <user> <key>   add a public key for a user");
    eprintln!("  change-port <port>           change the port sshd listens on");
    eprintln!();
    eprintln!("`run <task-id>` with no values prints what that task accepts.");
}

/// Executes a task against the detected system.
///
/// Shared by every task-running subcommand: detection, backend resolution and
/// the support check are identical regardless of which task runs.
fn execute(task: &dyn tasks::Task, values: &ParamValues) -> Result<()> {
    let distro = distro::detect::detect()?;

    if !task.supports(distro.family) {
        return Err(Error::TaskUnsupported {
            task: task.id().to_owned(),
            family: distro.family.to_string(),
        });
    }

    let backend = backend::for_distro(&distro);
    let executor = exec::local::LocalExecutor::new(exec::privilege::detect());

    let outcome = task.run(
        &executor,
        backend.as_ref(),
        values,
        &mut |line| match line.stream {
            exec::Stream::Stdout => println!("{}", line.text),
            exec::Stream::Stderr => eprintln!("{}", line.text),
        },
    )?;

    // The CLI has no verification window to offer — it is not interactive and
    // exits immediately — so it names the backup instead. An administrator who
    // finds themselves locked out needs the path, not a prompt they cannot
    // answer.
    if let Some(revert) = outcome.revert() {
        println!(
            "the previous {} was kept; restore it if you lose access",
            revert.describes()
        );
    }

    Ok(())
}

/// Authorises a public key for a user.
fn cmd_authorize_key(args: &[String]) -> Result<()> {
    let ([user, key_parts @ ..], false) = (args, args.len() < 2) else {
        eprintln!("authorize-key: a user and a public key are required");
        usage();
        std::process::exit(2);
    };

    let mut values = ParamValues::new();
    values.set(tasks::ssh::AuthorizeKey::USER, user.clone());
    // The key is taken as the remaining arguments joined, so an unquoted key
    // pasted on the command line still works.
    values.set(tasks::ssh::AuthorizeKey::KEY, key_parts.join(" "));

    execute(&tasks::ssh::AuthorizeKey, &values)
}

/// Changes the SSH port.
fn cmd_change_port(port: Option<&str>) -> Result<()> {
    let Some(port) = port else {
        eprintln!("change-port: a port number is required");
        usage();
        std::process::exit(2);
    };

    let Ok(port) = port.parse::<u32>() else {
        eprintln!("change-port: {port} is not a number");
        std::process::exit(2);
    };

    let mut values = ParamValues::new();
    values.set(tasks::ssh::ChangePort::PORT, port.to_string());

    execute(&tasks::ssh::ChangePort, &values)
}

/// Indentation applied per level of the task tree.
const LIST_INDENT: &str = "  ";

/// Lists the task tree and whether each task runs on this system.
fn cmd_list() -> Result<()> {
    let family = distro::detect::detect()?.family;

    let tree = tasks::tree();

    // Width is measured rather than fixed so a longer id added later cannot
    // silently break the alignment.
    let id_width = tasks::all_tasks()
        .iter()
        .map(|task| task.id().len())
        .max()
        .unwrap_or(0);

    print_nodes(&tree, family, id_width, 0);

    Ok(())
}

/// Prints a forest of nodes, indenting one level per depth.
fn print_nodes(nodes: &[tasks::Node], family: distro::Family, id_width: usize, depth: usize) {
    let indent = LIST_INDENT.repeat(depth);

    for node in nodes {
        match node {
            tasks::Node::Category(category) => {
                println!("{}{}:", indent, category.title);
                print_nodes(&category.children, family, id_width, depth + 1);
            }
            tasks::Node::Task(task) => {
                // Unsupported tasks stay visible with a reason, rather than
                // being hidden — the same rule the TUI follows.
                let mark = if task.supports(family) { " " } else { "!" };
                println!(
                    "{}[{}] {:<width$}  {}",
                    indent,
                    mark,
                    task.id(),
                    task.title(),
                    width = id_width
                );
            }
        }
    }
}

/// Runs a single task by identifier.
fn cmd_run(id: Option<&str>, rest: &[String]) -> Result<()> {
    let Some(id) = id else {
        eprintln!("run: a task id is required");
        usage();
        std::process::exit(2);
    };

    let Some(task) = tasks::find(id) else {
        eprintln!("unknown task: {id}");
        eprintln!("run `initd list` to see the available tasks");
        std::process::exit(2);
    };

    // Some tasks stay out of reach here whatever arguments are supplied. Both
    // apply a change that can end the session applying it, and the interactive
    // interface holds such a change open until the administrator proves from a
    // second session that they can still get in — reverting on its own when
    // they cannot. The CLI exits immediately, so it has no such window to
    // offer, and a mistake here is one nothing rolls back.
    if INTERACTIVE_ONLY.contains(&id) {
        eprintln!("{id} runs only in the interactive interface");
        eprintln!(
            "it applies a change that can end this session, and only the \
             interactive interface can hold it open for you to confirm"
        );
        std::process::exit(2);
    }

    let values = collect_values(task.as_ref(), rest);

    execute(task.as_ref(), &values)
}

/// Tasks the CLI refuses regardless of the arguments given.
///
/// Not a limitation of the argument parsing: each applies a change that can
/// end the session applying it, and only the interactive interface can hold
/// one open for confirmation and revert it unattended.
const INTERACTIVE_ONLY: [&str; 2] = ["ssh.allow-users", "users.lock-root"];

/// Reads `name=value` arguments into the values a task declared.
///
/// Validated against the task's own declaration rather than against a table
/// kept beside it: a name the task does not declare is a typo that would
/// otherwise be dropped silently, and a value that fails the same check the
/// interactive form applies is one the CLI must refuse for the same reason.
fn collect_values(task: &dyn tasks::Task, arguments: &[String]) -> ParamValues {
    let declared = task.params();
    let mut values = ParamValues::new();

    for argument in arguments {
        let Some((name, value)) = argument.split_once('=') else {
            eprintln!("{argument} is not a name=value pair");
            print_expected(task.id(), &declared);
            std::process::exit(2);
        };

        let Some(param) = declared.iter().find(|param| param.name == name) else {
            eprintln!("{} takes no parameter named {name}", task.id());
            print_expected(task.id(), &declared);
            std::process::exit(2);
        };

        // The same validation the interactive form runs. A CLI argument never
        // passes through the keystroke filter, so this is the only barrier
        // between it and a system file.
        if let Err(reason) = param.kind.validate(value) {
            eprintln!("{name}: {reason}");
            std::process::exit(2);
        }

        values.set(param.name, value.to_owned());
    }

    // Checked after parsing rather than before, so a command naming three of
    // four values is told which one is missing rather than being handed the
    // whole list again.
    let missing: Vec<&str> = declared
        .iter()
        .filter(|param| param.initial.is_empty() && values.get(param.name).is_err())
        .map(|param| param.name)
        .collect();

    if !missing.is_empty() {
        eprintln!("{} needs: {}", task.id(), missing.join(", "));
        print_expected(task.id(), &declared);
        std::process::exit(2);
    }

    // Defaults fill in last, so an explicit value always wins over one the
    // task merely suggests.
    for param in &declared {
        if !param.initial.is_empty() && values.get(param.name).is_err() {
            values.set(param.name, param.initial.clone());
        }
    }

    values
}

/// Prints what a task accepts, with its hints.
fn print_expected(id: &str, declared: &[tasks::params::Param]) {
    eprintln!();
    eprintln!("usage: initd run {id} [name=value ...]");

    for param in declared {
        let default = if param.initial.is_empty() {
            String::new()
        } else {
            format!(" (default: {})", param.initial)
        };

        let hint = param
            .hint
            .as_ref()
            .map_or(String::new(), |hint| format!(" — {hint}"));

        eprintln!("  {}{default}{hint}", param.name);
    }
}

/// Prints the privilege escalation mechanism resolved for this system.
fn cmd_privileges() -> Result<()> {
    let escalator = exec::privilege::detect();
    println!("escalation: {}", escalator.name());

    // Show what an install would actually spawn, which is the useful part
    // when diagnosing a system with an unusual setup.
    let sample = exec::Command::new("systemctl")
        .args(["enable", "ssh.service"])
        .privileged();

    match escalator.wrap(&sample) {
        Ok((program, args)) => println!("example:    {} {}", program, args.join(" ")),
        Err(err) => println!("example:    unavailable ({err})"),
    }

    // Run something harmless through the real executor, so this subcommand
    // also verifies that the execution path works end to end.
    use exec::Executor as _;

    let executor = exec::local::LocalExecutor::new(exec::privilege::detect());
    let output = executor.run(&exec::Command::new("id").arg("-u"))?;

    if output.success() {
        println!("effective uid: {}", output.stdout.trim());
    }

    Ok(())
}

/// Prints the detected distribution and its resolved family.
fn cmd_detect() -> Result<()> {
    let distro = distro::detect::detect()?;

    println!("distribution: {}", distro.display_name());
    println!("id:           {}", distro.id);
    println!(
        "version:      {}",
        distro.version_id.as_deref().unwrap_or("(rolling)")
    );
    println!("family:       {}", distro.family);

    Ok(())
}
