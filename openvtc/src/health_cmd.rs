//! `openvtc health` — resolve the messaging chain and print the map.
//!
//! The command exists for one question: a join went out, nothing came back,
//! and every service involved logged a clean run. Answering it means knowing
//! which DIDs resolve, what each one advertises, which transport any two of
//! them would actually negotiate, and whether they even share a mediator. That
//! is four `did.jsonl` fetches and a service-array diff done by hand, which is
//! why it usually isn't done.
//!
//! Config loading is **best-effort by design**. `--vtc` alone produces a useful
//! report against a community you have not joined (and against one whose join is
//! stuck), and a config that will not decrypt is itself a finding rather than a
//! reason to refuse to run.

use anyhow::Result;
use console::style;
use openvtc_core::config::{Config, KeyBackend};
use openvtc_core::health::{
    HealthReport, LinkOutcome, Party, Probe, ProbeGrade, Role, Step, Subject,
    build_report_with_progress,
};

use crate::colors::{CLI_BLUE, CLI_ORANGE, CLI_PURPLE, CLI_RED};

/// Build the subject list and render the report.
///
/// `config` is `None` when the account could not be loaded; the report then
/// covers only the `--vtc` DIDs given on the command line.
pub async fn run(config: Option<&Config>, vtc_args: &[String], as_json: bool) -> Result<()> {
    let mut subjects: Vec<Subject> = Vec::new();

    if let Some(config) = config {
        for identity in config.identities.values() {
            subjects.push(Subject::new(
                Role::Persona,
                format!("persona {}", short_tail(&identity.did)),
                identity.did.clone(),
            ));
        }
        if let KeyBackend::Vta { vta_did, .. } = &config.key_backend
            && vta_did.starts_with("did:")
        {
            subjects.push(Subject::new(Role::Vta, "VTA", vta_did.clone()));
        }
        for community in config.account.memberships() {
            let did = community.vtc_did.to_string();
            subjects.push(Subject::new(
                Role::Vtc,
                format!("VTC {} (joined)", short_tail(&did)),
                did,
            ));
        }
    }

    // Command-line VTCs last: `build_report` de-duplicates by DID and keeps the
    // first label, so a community already in the config keeps its "(joined)"
    // label rather than being relabelled by the flag that also named it.
    for did in vtc_args {
        subjects.push(Subject::new(
            Role::Vtc,
            format!("VTC {} (--vtc)", short_tail(did)),
            did.clone(),
        ));
    }

    if subjects.is_empty() {
        anyhow::bail!(
            "nothing to check: no account could be loaded and no --vtc was given. \
             Pass --vtc <did> to check a community directly."
        );
    }

    // Progress goes to stderr, the report to stdout. That keeps
    // `openvtc health --json > report.json` piping cleanly while still showing
    // the operator what is being waited on — and progress *is* wanted under
    // `--json`, since that is the run most likely to be watched rather than read.
    let report = build_report_with_progress(&subjects, &|step| trace(&step)).await;

    if as_json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        render(&report, config.is_none());
    }

    // A broken chain is a failed check: exit non-zero so this is usable in a
    // script or a CI smoke test, not only by eye.
    if report.is_healthy() {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

/// The last path segment of a `did:webvh`, which is the part humans recognise
/// (`…:dids.example.dev:legend-swear` → `legend-swear`). Falls back to the whole
/// string for DID methods with no path.
fn short_tail(did: &str) -> String {
    did.rsplit(':').next().unwrap_or(did).to_string()
}

/// Render one [`Step`] to stderr, unbuffered.
///
/// `eprintln!` flushes per call, which is what makes this live rather than a
/// batch dumped at exit — the whole point is that the operator sees the slow
/// step *while* it is slow.
///
/// Each wait is announced before it starts and its result carries the time it
/// took, because a chain that pauses nine seconds on one mediator and then
/// succeeds has told you something the final report cannot: the outcome is fine
/// and the host is struggling.
fn trace(step: &Step) {
    // `dim` rather than a palette colour: these lines are scaffolding the
    // operator reads past on a healthy run, and they must not compete with the
    // report that follows on stdout.
    let dim = |s: String| style(s).dim().to_string();
    match step {
        Step::ResolverStarting => {
            eprintln!("{}", dim("  · starting DID resolver…".into()));
        }
        Step::Resolving { role, label, did } => {
            eprintln!(
                "{}",
                dim(format!(
                    "  · resolving {} {label} ({})…",
                    role.as_str(),
                    truncate_did(did)
                ))
            );
        }
        Step::Resolved {
            label,
            services,
            transports,
            elapsed,
        } => {
            let transports = if transports.is_empty() {
                style("no known transport").color256(CLI_ORANGE).to_string()
            } else {
                style(protocols(transports))
                    .color256(CLI_PURPLE)
                    .to_string()
            };
            eprintln!(
                "    {} {label} — {services} service{}, {transports} {}",
                style("✓").color256(CLI_BLUE),
                if *services == 1 { "" } else { "s" },
                dim(secs(elapsed)),
            );
        }
        Step::ResolveFailed {
            label,
            error,
            elapsed,
        } => {
            eprintln!(
                "    {} {label} — {error} {}",
                style("✗").color256(CLI_RED).bold(),
                dim(secs(elapsed)),
            );
        }
        Step::FollowingMediators { count } => {
            if *count > 0 {
                eprintln!(
                    "{}",
                    dim(format!(
                        "  · following {count} discovered mediator{}…",
                        if *count == 1 { "" } else { "s" }
                    ))
                );
            }
        }
        Step::Probing { url } => {
            eprintln!("{}", dim(format!("  · probing {url}…")));
        }
        Step::Probed { probe, elapsed } => match probe {
            Probe::Reachable { url, http_status } => {
                let (word, colour) = probe_words(probe);
                let mark = if probe.grade() == Some(ProbeGrade::ServerError) {
                    style("!").color256(CLI_ORANGE).bold()
                } else {
                    style("✓").color256(CLI_BLUE)
                };
                eprintln!(
                    "    {mark} {url} — {} (HTTP {http_status}) {}",
                    style(word).color256(colour),
                    dim(secs(elapsed)),
                );
            }
            Probe::Unreachable { url, error } => eprintln!(
                "    {} {url} — {error} {}",
                style("✗").color256(CLI_RED).bold(),
                dim(secs(elapsed)),
            ),
        },
        Step::Negotiating { pairs } => {
            if *pairs > 0 {
                eprintln!(
                    "{}",
                    dim(format!(
                        "  · negotiating {pairs} pair{}…",
                        if *pairs == 1 { "" } else { "s" }
                    ))
                );
            }
        }
        Step::Finished { elapsed } => {
            eprintln!(
                "{}",
                dim(format!("  · done in {:.1}s", elapsed.as_secs_f64()))
            );
            eprintln!();
        }
        // `Step` is `#[non_exhaustive]`: a variant added upstream should be
        // silent here rather than stopping the build of a diagnostic tool.
        _ => {}
    }
}

/// A duration at the precision that matters for a network wait — tenths.
/// Anything finer is noise next to a 10s timeout.
fn secs(elapsed: &std::time::Duration) -> String {
    format!("({:.1}s)", elapsed.as_secs_f64())
}

/// Shorten a DID for a progress line: the method, an ellipsis, and the trailing
/// path segment that identifies it. A full `did:webvh` is ~110 characters and
/// wraps the terminal, which is what makes a live trace unreadable.
fn truncate_did(did: &str) -> String {
    if did.len() <= 48 {
        return did.to_string();
    }
    let tail = short_tail(did);
    let head: String = did.chars().take(20).collect();
    format!("{head}…{tail}")
}

fn render(report: &HealthReport, config_missing: bool) {
    if config_missing {
        println!(
            "{}",
            style(
                "No account loaded — reporting only the DIDs given with --vtc. \
                 Persona, VTA and mediator legs are not covered."
            )
            .color256(CLI_ORANGE)
        );
        println!();
    }

    println!("{}", style("PARTIES").color256(CLI_BLUE).bold());
    for party in &report.parties {
        render_party(party);
    }

    if !report.links.is_empty() {
        println!();
        println!(
            "{}",
            style("NEGOTIATED TRANSPORT").color256(CLI_BLUE).bold()
        );
        for link in &report.links {
            let arrow = format!("  {} → {}", link.from, link.to);
            match &link.outcome {
                LinkOutcome::Selected {
                    protocol,
                    peer_endpoint,
                } => println!(
                    "{arrow}: {} via {}",
                    style(protocol.as_str()).color256(CLI_PURPLE).bold(),
                    style(peer_endpoint).color256(CLI_PURPLE),
                ),
                LinkOutcome::NoCommonProtocol { ours, theirs } => println!(
                    "{arrow}: {} (we offer [{}], they offer [{}])",
                    style("no shared transport").color256(CLI_RED).bold(),
                    protocols(ours),
                    protocols(theirs),
                ),
                LinkOutcome::Unknown { reason } => println!(
                    "{arrow}: {} ({reason})",
                    style("unknown").color256(CLI_ORANGE)
                ),
            }
        }
    }

    println!();
    if report.notes.is_empty() {
        println!(
            "{}",
            style("No problems found in the messaging chain.").color256(CLI_BLUE)
        );
    } else {
        println!("{}", style("FINDINGS").color256(CLI_ORANGE).bold());
        for note in &report.notes {
            println!("  • {note}");
        }
    }
}

fn render_party(party: &Party) {
    println!();
    println!(
        "  {} {}",
        style(format!("[{}]", party.role.as_str())).color256(CLI_PURPLE),
        style(&party.label).bold(),
    );
    println!("    did: {}", style(&party.did).color256(CLI_PURPLE));

    let Some(resolved) = &party.resolved else {
        println!(
            "    {}: {}",
            style("UNRESOLVED").color256(CLI_RED).bold(),
            party.error.as_deref().unwrap_or("unknown error"),
        );
        return;
    };

    if resolved.services.is_empty() {
        println!("    services: {}", style("none").color256(CLI_RED));
    } else {
        println!("    services:");
        for service in &resolved.services {
            let types = if service.types.is_empty() {
                "<no type>".to_string()
            } else {
                service.types.join(", ")
            };
            // The `#id` fragment is shown but never matched on — an operator
            // comparing two deployments needs to see that one names it `#tsp`
            // and the other `#tsp-transport` while both are `TSPTransport`.
            println!(
                "      {:<28} {:<22} → {}",
                fragment(&service.id),
                style(types).color256(CLI_BLUE),
                service.endpoint,
            );
        }
    }

    for probe in &resolved.probes {
        match probe {
            Probe::Reachable { url, http_status } => {
                let (word, colour) = probe_words(probe);
                println!(
                    "    probe {url} → {} (HTTP {http_status})",
                    style(word).color256(colour),
                );
            }
            Probe::Unreachable { url, error } => println!(
                "    probe {url} → {} ({error})",
                style("unreachable").color256(CLI_RED).bold(),
            ),
        }
    }
}

/// The verdict word and colour for a probe.
///
/// "reachable (HTTP 404)" read as a contradiction — the word claimed health and
/// the number denied it, and nothing told the reader which to believe. The word
/// now carries the grade, so a mediator base path answering 404 says
/// "responding", which is exactly what it is: the host is there and that path
/// does not serve GETs.
fn probe_words(probe: &Probe) -> (&'static str, u8) {
    match probe.grade() {
        Some(ProbeGrade::Ok) => ("ok", CLI_BLUE),
        Some(ProbeGrade::Responding) => ("responding", CLI_BLUE),
        Some(ProbeGrade::ServerError) => ("server error", CLI_ORANGE),
        None => ("unreachable", CLI_RED),
    }
}

/// Just the `#fragment` of a service id when it has one — the full DID prefix is
/// already printed above and repeating it per row buries the part that differs.
fn fragment(id: &str) -> String {
    match id.rsplit_once('#') {
        Some((_, frag)) => format!("#{frag}"),
        None => id.to_string(),
    }
}

fn protocols(list: &[vta_sdk::protocol::matching::Protocol]) -> String {
    if list.is_empty() {
        return "none".to_string();
    }
    list.iter()
        .map(|p| p.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_tail_names_a_webvh_persona_by_its_path() {
        assert_eq!(
            short_tail("did:webvh:QmScid:dids.example.dev:legend-swear"),
            "legend-swear"
        );
    }

    /// A DID with no path must not render as an empty label.
    #[test]
    fn short_tail_falls_back_for_pathless_dids() {
        assert_eq!(short_tail("did:key:z6Mkabc"), "z6Mkabc");
        assert_eq!(short_tail("notadid"), "notadid");
    }

    /// The fragment is what distinguishes two service entries; the DID prefix is
    /// printed once above and repeating it per row hides the difference.
    #[test]
    fn service_ids_render_as_their_fragment() {
        assert_eq!(fragment("did:webvh:QmScid:example:x#tsp"), "#tsp");
        assert_eq!(
            fragment("did:webvh:QmScid:example:x#tsp-transport"),
            "#tsp-transport",
            "the OWF reference impl names it differently from ours; both are \
             TSPTransport, and an operator comparing deployments must see which"
        );
        assert_eq!(fragment("no-fragment"), "no-fragment");
    }
}
