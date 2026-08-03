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
        Some("detect") => cmd_detect(),
        Some("privileges") => cmd_privileges(),
        Some("list") => cmd_list(),
        Some("run") => cmd_run(args.get(1).map(String::as_str)),
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

/// Prints the available subcommands.
fn usage() {
    eprintln!("usage: initd <command>");
    eprintln!();
    eprintln!("  detect                       show the detected distribution");
    eprintln!("  privileges                   show the privilege escalation mechanism");
    eprintln!("  list                         list the available tasks");
    eprintln!("  run <task-id>                run a task that takes no arguments");
    eprintln!("  authorize-key <user> <key>   add a public key for a user");
    eprintln!("  change-port <port>           change the port sshd listens on");
}

/// Executes a task against the detected system.
///
/// Shared by every task-running subcommand: detection, backend resolution and
/// the support check are identical regardless of which task runs.
fn execute(task: &dyn tasks::Task) -> Result<()> {
    let distro = distro::detect::detect()?;

    if !task.supports(distro.family) {
        return Err(Error::TaskUnsupported {
            task: task.id().to_owned(),
            family: distro.family.to_string(),
        });
    }

    let backend = backend::for_family(distro.family);
    let executor = exec::local::LocalExecutor::new(exec::privilege::detect());

    task.run(&executor, backend.as_ref(), &mut |line| match line.stream {
        exec::Stream::Stdout => println!("{}", line.text),
        exec::Stream::Stderr => eprintln!("{}", line.text),
    })
}

/// Authorises a public key for a user.
fn cmd_authorize_key(args: &[String]) -> Result<()> {
    let ([user, key_parts @ ..], false) = (args, args.len() < 2) else {
        eprintln!("authorize-key: a user and a public key are required");
        usage();
        std::process::exit(2);
    };

    // The key is taken as the remaining arguments joined, so an unquoted key
    // pasted on the command line still works.
    execute(&tasks::ssh::AuthorizeKey {
        user: user.clone(),
        key: key_parts.join(" "),
    })
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

    execute(&tasks::ssh::ChangePort { port })
}

/// Lists the task tree and whether each task runs on this system.
fn cmd_list() -> Result<()> {
    let family = distro::detect::detect()?.family;

    let tree = tasks::tree();

    // Width is measured rather than fixed so a longer id added later cannot
    // silently break the alignment.
    let id_width = tree
        .iter()
        .flat_map(|group| &group.tasks)
        .map(|task| task.id().len())
        .max()
        .unwrap_or(0);

    for group in &tree {
        println!("{}:", group.title);

        for task in &group.tasks {
            // Unsupported tasks stay visible with a reason, rather than being
            // hidden — the same rule the TUI follows.
            let mark = if task.supports(family) { " " } else { "!" };
            println!(
                "  [{}] {:<width$}  {}",
                mark,
                task.id(),
                task.title(),
                width = id_width
            );
        }
    }

    Ok(())
}

/// Runs a single task by identifier.
fn cmd_run(id: Option<&str>) -> Result<()> {
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

    execute(task.as_ref())
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
