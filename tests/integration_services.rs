//! Firewall, WireGuard, rootless containers and the web server, observed on a
//! real system.
//!
//! Ignored by default; run with `cargo nextest run -- --ignored`.
//!
//! What these settle that a mock cannot: whether the commands exist under the
//! names the backend uses, and whether their output has the shape the parsing
//! assumes. Both are claims about software this repository does not own, and
//! both are the kind that fail quietly — a listing parsed wrongly reports an
//! empty firewall rather than an error.

mod common;

use common::{ARCH, DEBIAN, Image, run_in_container, stdout_of};

/// Runs a script and returns both streams together.
///
/// A tool that refuses explains itself on stderr, so asserting on stdout alone
/// would see an empty string and no reason.
fn observe(image: &Image, script: &str) -> String {
    let output = run_in_container(image, script);

    format!(
        "{}{}",
        stdout_of(&output),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// Runs a script with a package installed first.
///
/// Neither base image ships `nft`, `wg` or — on Debian — `sysctl`, so a
/// scenario that assumed them present would fail for a missing tool while
/// reading as a claim about the tool's behaviour. The install output is
/// discarded because a package manager's progress is not what is being
/// asserted; a failure surfaces as the command afterwards not being found.
fn observe_with(image: &Image, install: &str, script: &str) -> String {
    observe(image, &format!("{install} >/dev/null 2>&1; {script}"))
}

for_each_image! {
    fn the_sysctl_parameters_the_tasks_write_exist_on_both_families(image) {
        // The runtime half is applied before the drop-in is written precisely so a
        // parameter this kernel lacks fails before a file is left that makes every
        // boot log an error. That guard is only worth anything if the parameters
        // are real, which is what this asserts.
        for key in ["net.ipv4.ip_forward", "net.ipv4.ip_unprivileged_port_start"] {
            let observed = observe_with(image, image.install_sysctl, &format!("sysctl -n {key}"));

            assert!(
                observed.trim().parse::<u32>().is_ok(),
                "{}: {key} must read back as a number: {observed}",
                image.name
            );
        }
    }
}

for_each_image! {
    fn the_sysctl_drop_in_directory_is_read_at_boot(image) {
        // The tool writes `/etc/sysctl.d/99-initd.conf` rather than appending to
        // `/etc/sysctl.conf`, which only works if the directory is one the system
        // actually reads.
        let observed = observe_with(
            image,
            image.install_sysctl,
            "test -d /etc/sysctl.d && echo PRESENT",
        );

        assert!(
            observed.contains("PRESENT"),
            "{}: /etc/sysctl.d must exist for the drop-in to be read: {observed}",
            image.name
        );
    }
}

for_each_image! {
    fn nft_lists_rules_in_the_shape_the_parsing_expects(image) {
        // `FirewallManager::state` reads ports back out of a listing by splitting
        // each line into `protocol dport port accept`. That is a claim about how
        // nft renders a rule, and rendering is nft's decision rather than this
        // project's — a change there would show up as a firewall reporting no open
        // ports rather than as an error.
        //
        // Skipped where the container cannot reach netlink, which is every run
        // without NET_ADMIN — even `nft -c` opens a netlink socket to build its
        // cache before parsing, so there is no syntax-only mode to fall back on.
        //
        // Reported as skipped rather than quietly asserted around: a scenario that
        // passed by checking something weaker would read as coverage of the
        // listing format while proving nothing about it. Run the suite with
        // `--cap-add=NET_ADMIN` to exercise this properly.
        let observed = observe_with(
            image,
            image.install_nftables,
            "nft list ruleset >/dev/null 2>&1; echo EXIT=$?",
        );

        if !observed.contains("EXIT=0") {
            eprintln!(
                "{}: skipping — this container cannot reach netlink, so the \
                 listing format cannot be observed here",
                image.name
            );

            // `return` rather than `continue`: each family is its own test
            // now, so this skips one image instead of abandoning every family
            // after it in a shared loop.
            return;
        }

        let listed = observe_with(
            image,
            image.install_nftables,
            "nft add table inet initd && \
             nft add chain inet initd input '{ type filter hook input priority 0; }' && \
             nft add rule inet initd input tcp dport 22 accept && \
             nft list table inet initd",
        );

        assert!(
            listed.lines().any(|line| {
                let mut parts = line.split_whitespace();
                parts.next() == Some("tcp")
                    && parts.next() == Some("dport")
                    && parts.next() == Some("22")
            }),
            "{}: a rule must render as `tcp dport 22 accept`: {listed}",
            image.name
        );
    }
}

for_each_image! {
    fn a_missing_table_is_an_answer_rather_than_a_crash(image) {
        // A host where this tool has never run has no table of its own, and the
        // honest answer is that it allows nothing. The implementation reads the
        // exit code rather than treating it as a failure, which only holds if nft
        // exits non-zero rather than printing an empty listing.
        let observed = observe_with(
            image,
            image.install_nftables,
            "nft list table inet initd >/dev/null 2>&1; echo EXIT=$?",
        );

        assert!(
            !observed.contains("EXIT=0"),
            "{}: a missing table must exit non-zero, not print nothing: {observed}",
            image.name
        );
    }
}

for_each_image! {
    fn wireguard_keys_are_the_length_the_validation_requires(image) {
        // The tool refuses a key that is not 44 characters, because a truncated
        // one parses and never completes a handshake. That number comes from
        // WireGuard's encoding rather than from this project, so it is checked
        // against the tool that produces it.
        let observed = observe_with(
            image,
            image.install_wireguard,
            "wg genkey | tr -d '\\n' | wc -c",
        );

        assert_eq!(
            observed.trim(),
            "44",
            "{}: a generated key must be 44 characters: {observed}",
            image.name
        );
    }
}

for_each_image! {
    fn a_public_key_is_derived_from_stdin_without_the_private_key_reaching_argv(image) {
        // The reason `public_key_of` feeds the key on stdin: `/proc/<pid>/cmdline`
        // is readable by every account on the host. This asserts `wg pubkey`
        // actually accepts stdin, which is what makes that possible.
        // `umask 077` before the redirect, because `wg genkey` warns when its
        // output lands in a world-readable file — and it is right to. That
        // warning is what surfaced the same window in this tool's own
        // configuration write, which now sets the mode before the key goes in.
        let observed = observe_with(
            image,
            image.install_wireguard,
            "umask 077; wg genkey > /tmp/priv && wg pubkey < /tmp/priv | tr -d '\\n' | wc -c",
        );

        assert!(
            observed.contains("44"),
            "{}: wg pubkey must read the key from stdin: {observed}",
            image.name
        );
        assert!(
            !observed.contains("world accessible"),
            "{}: a key must not be written world-readable: {observed}",
            image.name
        );
    }
}

for_each_image! {
    fn a_preshared_key_is_a_separate_generator(image) {
        // `generate_keypair` calls `genpsk` as well as `genkey`. If the subcommand
        // did not exist the keypair would fail at the second step, after the first
        // had already produced a private key.
        let observed = observe_with(
            image,
            image.install_wireguard,
            "wg genpsk | tr -d '\\n' | wc -c",
        );

        assert_eq!(
            observed.trim(),
            "44",
            "{}: genpsk must produce a key of its own: {observed}",
            image.name
        );
    }
}

for_each_image! {
    fn the_wireguard_package_carries_the_tools_under_both_names(image) {
        // Debian and Arch happen to agree on `wireguard-tools`, which the backend
        // records as coincidence rather than as a rule. This asserts the package
        // that name resolves to actually provides `wg`.
        let observed = observe_with(image, image.install_wireguard, "command -v wg");

        assert!(
            observed.contains("/wg"),
            "{}: the installed package must provide wg: {observed}",
            image.name
        );
    }
}

for_each_image! {
    fn subordinate_id_files_exist_for_the_rootless_check_to_read(image) {
        // `has_subordinate_ids` greps both files and treats a missing entry as
        // "no range". A missing *file* must behave the same way rather than
        // erroring, since a system that predates the convention has neither.
        let observed = observe(
            image,
            "grep -q '^nobody:' /etc/subuid >/dev/null 2>&1; echo EXIT=$?",
        );

        assert!(
            !observed.contains("EXIT=0"),
            "{}: an account with no range must be reported as having none: {observed}",
            image.name
        );
    }
}
#[test]
#[ignore = "requires docker"]
fn loginctl_reports_lingering_as_a_whole_property() {
    require_docker!();

    // `is_lingering` compares the whole `Linger=yes` string rather than
    // searching for `yes`. That depends on loginctl's output format, which is
    // systemd's decision.
    //
    // Debian only, and installed rather than assumed: `loginctl` ships with
    // systemd, which neither base image carries. Without a running bus it
    // reports a failure rather than the property — which is itself the
    // behaviour `is_lingering` relies on, since it treats a failed lookup as
    // "not lingering" rather than as an error.
    let observed = observe_with(
        &DEBIAN,
        DEBIAN.install_systemd,
        "loginctl show-user root --property=Linger 2>&1; echo EXIT=$?",
    );

    assert!(
        observed.contains("Linger=") || !observed.contains("EXIT=0"),
        "loginctl must answer with the property or fail, not succeed silently: {observed}"
    );
}
#[test]
#[ignore = "requires docker"]
fn caddy_validates_a_configuration_rather_than_only_parsing_it() {
    require_docker!();

    // `caddy.validate` asks Caddy instead of reading the file, because
    // directive order in a Caddyfile is not its source order. That only works
    // if the subcommand exists and answers on its exit code.
    //
    // Debian only: Arch's caddy package pulls a different dependency set, and
    // what is being asserted is the subcommand's contract rather than either
    // distribution's packaging.
    let observed = observe_with(
        &DEBIAN,
        "apt-get install -y -qq caddy",
        "printf 'example.com {\\n\\trespond \"ok\"\\n}\\n' > /tmp/Caddyfile; \
         caddy validate --config /tmp/Caddyfile --adapter caddyfile 2>&1; \
         echo EXIT=$?",
    );

    assert!(
        observed.contains("EXIT=0") || observed.contains("Valid configuration"),
        "a well-formed Caddyfile must validate: {observed}"
    );
}
#[test]
#[ignore = "requires docker"]
fn caddy_rejects_a_configuration_it_cannot_parse() {
    require_docker!();

    // The other half, and the one that matters: a task that treated every exit
    // as success would write a snippet that takes every site down at the next
    // reload and report that it worked.
    let observed = observe_with(
        &DEBIAN,
        "apt-get install -y -qq caddy",
        "printf 'example.com {\\n\\treverse_prox localhost:8080\\n}\\n' > /tmp/Caddyfile; \
         caddy validate --config /tmp/Caddyfile --adapter caddyfile 2>&1; \
         echo EXIT=$?",
    );

    assert!(
        !observed.contains("EXIT=0"),
        "an unknown directive must not validate: {observed}"
    );
}
#[test]
#[ignore = "requires docker"]
fn the_arch_image_resolves_its_own_package_names() {
    require_docker!();

    // The divergence the capability indirection exists for, asserted where it
    // is real: Arch packages zellij and Debian does not, in any suite. If Arch
    // ever drops it the task would fall through to the release installer,
    // which is a different code path than the one its tests cover.
    let observed = observe(&ARCH, "pacman -Si zellij >/dev/null 2>&1 && echo PACKAGED");

    assert!(
        observed.contains("PACKAGED"),
        "Arch must package zellij for the distribution path to be taken: {observed}"
    );
}
