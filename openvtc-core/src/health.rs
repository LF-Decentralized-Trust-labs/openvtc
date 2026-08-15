//! Map the messaging path between OpenVTC and a community, and say where it
//! breaks.
//!
//! A join that goes out and is never answered has, from the client, exactly one
//! symptom: nothing happens. The cause is somewhere in a chain of five or six
//! parties — this persona, its mediator, the VTA, the VTC, *its* mediator — each
//! of which advertises its own transports in its own DID document, and any two
//! of which may sit behind different mediators. Reading that by hand means
//! fetching several `did.jsonl` files and diffing service arrays.
//!
//! This module fetches them and prints the map. It answers four questions:
//!
//! 1. **Does each DID resolve?** For `did:webvh` that is a live HTTPS fetch, so
//!    it doubles as the first reachability check.
//! 2. **What does each advertise?** The full `service` array, verbatim — not
//!    just the transports we recognise, because an unrecognised entry is exactly
//!    what you want to see when a peer looks healthy and isn't.
//! 3. **What would we actually use?** [`select_protocol`] over both sides'
//!    capabilities, which is the same negotiation a real send performs.
//! 4. **Is the transport host reachable?** A bounded HTTP probe of each
//!    mediator's endpoint URL.
//!
//! Deliberately read-only: it resolves, negotiates and probes. It never sends a
//! message, so it is safe to run against production while a join is stuck.

use std::collections::BTreeSet;
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use serde::Serialize;
use serde_json::Value;
use vta_sdk::protocol::matching::{Protocol, ServiceCapabilities, select_protocol};

/// Bound on any single network step. Every step is independently bounded so one
/// unreachable host cannot stall the whole report — a partial map is the useful
/// output here, and a hang is the least useful.
const STEP_TIMEOUT: Duration = Duration::from_secs(10);

/// What a party is in the chain. Ordering is the order they are reported in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// One of our own persona DIDs — the identity a community knows us by.
    Persona,
    /// The Verifiable Trust Agent that custodies our keys.
    Vta,
    /// A community's VTC.
    Vtc,
    /// A mediator some other party routes through.
    Mediator,
}

impl Role {
    /// Lowercase display name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Persona => "persona",
            Role::Vta => "vta",
            Role::Vtc => "vtc",
            Role::Mediator => "mediator",
        }
    }
}

/// One `service` entry, as published. `types` is a vector because DID-Core
/// permits `type` to be a string or an array, and a party that publishes both
/// `TSPTransport` and something else on one entry is worth seeing as-is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServiceEntry {
    pub id: String,
    pub types: Vec<String>,
    pub endpoint: String,
}

/// Result of a bounded HTTP probe of a transport URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum Probe {
    /// The host answered. Any status is reachability — a 404 from a mediator's
    /// base path still proves DNS, TLS and routing all work, which is the thing
    /// being tested. Reporting it as a failure would send an operator hunting a
    /// network fault that isn't there.
    Reachable { url: String, http_status: u16 },
    /// No answer: DNS, TLS, connection or timeout.
    Unreachable { url: String, error: String },
}

/// A resolved party.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Resolved {
    /// Every `service` entry the document publishes, in document order.
    pub services: Vec<ServiceEntry>,
    /// The transports we recognise, by service `type`.
    pub tsp_endpoint: Option<String>,
    pub didcomm_endpoint: Option<String>,
    pub rest_endpoint: Option<String>,
    /// Probes of any `http(s)` endpoints above. Mediator DIDs are not probed
    /// here — they are separate parties in the report and probed as themselves.
    pub probes: Vec<Probe>,
}

/// A party in the chain, resolved or not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Party {
    pub role: Role,
    /// Where this DID came from — "persona", "VTC (--vtc)", "mediator of
    /// persona joy-ahead". Carries the provenance a bare DID cannot.
    pub label: String,
    pub did: String,
    /// `None` when resolution failed; `error` then says why.
    pub resolved: Option<Resolved>,
    pub error: Option<String>,
}

impl Party {
    /// The capability set for negotiation, or an empty one if unresolved.
    fn caps(&self) -> ServiceCapabilities {
        match &self.resolved {
            Some(r) => ServiceCapabilities {
                tsp: r.tsp_endpoint.clone(),
                didcomm: r.didcomm_endpoint.clone(),
                rest: r.rest_endpoint.clone(),
            },
            None => ServiceCapabilities::default(),
        }
    }
}

/// The negotiated transport between two parties.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum LinkOutcome {
    /// Both sides advertise it; this is what a send would pick.
    Selected {
        protocol: Protocol,
        /// The peer endpoint for that protocol — a mediator DID for TSP and
        /// DIDComm, a URL for REST.
        peer_endpoint: String,
    },
    /// The advertised sets do not intersect. Both are named so the operator can
    /// see which side to change.
    NoCommonProtocol {
        ours: Vec<Protocol>,
        theirs: Vec<Protocol>,
    },
    /// One side did not resolve, so there is nothing to negotiate over.
    Unknown { reason: String },
}

/// A directed pair whose transport we negotiated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Link {
    pub from: String,
    pub to: String,
    #[serde(flatten)]
    pub outcome: LinkOutcome,
}

/// The whole map.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HealthReport {
    pub parties: Vec<Party>,
    pub links: Vec<Link>,
    /// Findings worth an operator's attention — split mediators, dead ends,
    /// unresolvable parties. Empty is the healthy case.
    pub notes: Vec<String>,
}

impl HealthReport {
    /// Whether anything in the chain is broken enough to stop a message.
    ///
    /// Unresolvable parties and empty protocol intersections count; an
    /// unreachable probe does not, because a mediator that refuses a bare GET on
    /// its base path is normal and the DID resolution above already proved the
    /// host answers.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.parties.iter().all(|p| p.resolved.is_some())
            && !self
                .links
                .iter()
                .any(|l| matches!(l.outcome, LinkOutcome::NoCommonProtocol { .. }))
    }
}

/// A DID to include in the report, with the provenance to label it by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    pub role: Role,
    pub label: String,
    pub did: String,
}

impl Subject {
    pub fn new(role: Role, label: impl Into<String>, did: impl Into<String>) -> Self {
        Self {
            role,
            label: label.into(),
            did: did.into(),
        }
    }
}

/// Resolve every subject, follow each one's mediators, negotiate every link that
/// matters, and probe the transport hosts.
///
/// `subjects` is the chain as the caller knows it — our personas, our VTA, the
/// community's VTC. Mediators are *discovered*, not passed in: which mediator a
/// party uses is a property of its document, and taking it from local config
/// would report what we believe rather than what is published. That difference
/// is one of the things this command exists to expose.
pub async fn build_report(subjects: &[Subject]) -> HealthReport {
    let resolver = match DIDCacheClient::new(
        affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder::default().build(),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            return HealthReport {
                parties: Vec::new(),
                links: Vec::new(),
                notes: vec![format!(
                    "could not start a DID resolver ({e}) — nothing could be checked. \
                     This is a local fault, not a fault in the chain."
                )],
            };
        }
    };

    let http = reqwest::Client::builder()
        .timeout(STEP_TIMEOUT)
        .build()
        .ok();

    let mut parties: Vec<Party> = Vec::new();
    for subject in subjects {
        if subject.did.is_empty() {
            continue;
        }
        if parties.iter().any(|p| p.did == subject.did) {
            continue;
        }
        parties.push(resolve_party(&resolver, http.as_ref(), subject).await);
    }

    // Second pass: every mediator any resolved party routes through, resolved
    // once and labelled with *every* party that named it and for which
    // transports. Mapping who shares a mediator with whom is most of the point —
    // labelling it "TSP mediator of <first party to mention it>" would hide both
    // that it also carries that party's DIDComm and that a second party is
    // behind the same host.
    let referenced = mediator_references(&parties);
    for (did, users) in referenced {
        if parties.iter().any(|p| p.did == did) {
            continue;
        }
        let subject = Subject::new(Role::Mediator, format!("mediator of {users}"), did);
        parties.push(resolve_party(&resolver, http.as_ref(), &subject).await);
    }

    let links = negotiate_links(&parties);
    let notes = collect_notes(&parties, &links);
    HealthReport {
        parties,
        links,
        notes,
    }
}

/// Which mediator DIDs the resolved parties route through, and who routes to
/// each — `did:webvh:…:mediator` → `"persona joy-ahead (TSP, DIDComm), VTC acme
/// (DIDComm)"`.
///
/// Keyed by DID so a mediator shared by several parties is resolved and probed
/// once. Only `did:` endpoints qualify: a URL endpoint *is* the transport, and
/// belongs to (and was probed on) the party that published it.
///
/// `BTreeMap` throughout for a stable report; the protocol list is a `Vec` built
/// in preference order rather than a set, because "TSP, DIDComm" reads as the
/// negotiation order and "DIDComm, TSP" (alphabetical) does not.
fn mediator_references(parties: &[Party]) -> std::collections::BTreeMap<String, String> {
    let mut refs: std::collections::BTreeMap<String, Vec<(String, Vec<&'static str>)>> =
        std::collections::BTreeMap::new();

    for party in parties {
        let Some(resolved) = &party.resolved else {
            continue;
        };
        for (protocol, endpoint) in [
            ("TSP", resolved.tsp_endpoint.as_deref()),
            ("DIDComm", resolved.didcomm_endpoint.as_deref()),
        ] {
            let Some(endpoint) = endpoint else { continue };
            if !endpoint.starts_with("did:") {
                continue;
            }
            let users = refs.entry(endpoint.to_string()).or_default();
            match users.iter_mut().find(|(label, _)| *label == party.label) {
                Some((_, protocols)) => protocols.push(protocol),
                None => users.push((party.label.clone(), vec![protocol])),
            }
        }
    }

    refs.into_iter()
        .map(|(did, users)| {
            let described = users
                .into_iter()
                .map(|(label, protocols)| format!("{label} ({})", protocols.join(", ")))
                .collect::<Vec<_>>()
                .join(", ");
            (did, described)
        })
        .collect()
}

/// Resolve one DID and read everything the report needs off its document.
async fn resolve_party(
    resolver: &DIDCacheClient,
    http: Option<&reqwest::Client>,
    subject: &Subject,
) -> Party {
    let fail = |error: String| Party {
        role: subject.role,
        label: subject.label.clone(),
        did: subject.did.clone(),
        resolved: None,
        error: Some(error),
    };

    let resolved = match tokio::time::timeout(STEP_TIMEOUT, resolver.resolve(&subject.did)).await {
        Ok(Ok(resolved)) => resolved,
        Ok(Err(e)) => return fail(e.to_string()),
        Err(_) => {
            return fail(format!(
                "resolution timed out after {}s",
                STEP_TIMEOUT.as_secs()
            ));
        }
    };
    let doc = match serde_json::to_value(&resolved.doc) {
        Ok(doc) => doc,
        Err(e) => return fail(format!("document could not be re-serialised: {e}")),
    };

    let caps = ServiceCapabilities::from_did_document(&doc);
    let services = service_entries(&doc);

    // Probe only endpoints that are URLs. A DID endpoint is a mediator, which
    // becomes its own party and is probed there — following it here would probe
    // the same host once per party that names it.
    let mut probes = Vec::new();
    if let Some(client) = http {
        let urls: BTreeSet<&str> = services
            .iter()
            .map(|s| s.endpoint.as_str())
            .filter(|e| e.starts_with("http://") || e.starts_with("https://"))
            .collect();
        for url in urls {
            probes.push(probe(client, url).await);
        }
    }

    Party {
        role: subject.role,
        label: subject.label.clone(),
        did: subject.did.clone(),
        resolved: Some(Resolved {
            services,
            tsp_endpoint: caps.tsp,
            didcomm_endpoint: caps.didcomm,
            rest_endpoint: caps.rest,
            probes,
        }),
        error: None,
    }
}

/// Read the `service` array verbatim.
///
/// Deliberately not filtered to the types we understand: a party that publishes
/// a transport this build does not know about looks, through
/// [`ServiceCapabilities`] alone, exactly like a party that publishes nothing —
/// and telling those two apart is most of the value of a map.
fn service_entries(doc: &Value) -> Vec<ServiceEntry> {
    let Some(services) = doc.get("service").and_then(Value::as_array) else {
        return Vec::new();
    };
    services
        .iter()
        .map(|svc| {
            let id = svc
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("<no id>")
                .to_string();
            let types = match svc.get("type") {
                Some(Value::String(s)) => vec![s.clone()],
                Some(Value::Array(arr)) => arr
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect(),
                _ => Vec::new(),
            };
            let endpoint = svc
                .get("serviceEndpoint")
                .and_then(endpoint_uri)
                .unwrap_or_else(|| "<unreadable>".to_string());
            ServiceEntry {
                id,
                types,
                endpoint,
            }
        })
        .collect()
}

/// The three shapes a `serviceEndpoint` may take: a string, an object with
/// `uri`, or an array of either. Mirrors `vta_sdk`'s private `endpoint_uri`.
fn endpoint_uri(endpoint: &Value) -> Option<String> {
    match endpoint {
        Value::String(s) => Some(s.clone()),
        Value::Object(map) => map.get("uri")?.as_str().map(str::to_string),
        Value::Array(arr) => arr.iter().find_map(endpoint_uri),
        _ => None,
    }
}

/// A bounded GET. Any HTTP answer is reachability — see [`Probe::Reachable`].
async fn probe(client: &reqwest::Client, url: &str) -> Probe {
    match client.get(url).send().await {
        Ok(response) => Probe::Reachable {
            url: url.to_string(),
            http_status: response.status().as_u16(),
        },
        Err(e) => Probe::Unreachable {
            url: url.to_string(),
            error: e.to_string(),
        },
    }
}

/// Negotiate the pairs that decide whether a join can complete: each persona
/// against each VTA and VTC.
///
/// Mediator-to-party pairs are deliberately absent. A mediator is a hop, not a
/// counterparty — nothing negotiates a protocol *with* it — and listing those
/// pairs would bury the two that matter.
fn negotiate_links(parties: &[Party]) -> Vec<Link> {
    let personas: Vec<&Party> = parties.iter().filter(|p| p.role == Role::Persona).collect();
    let peers: Vec<&Party> = parties
        .iter()
        .filter(|p| matches!(p.role, Role::Vta | Role::Vtc))
        .collect();

    let mut links = Vec::new();
    for persona in &personas {
        for peer in &peers {
            let outcome = if persona.resolved.is_none() {
                LinkOutcome::Unknown {
                    reason: format!("{} did not resolve", persona.label),
                }
            } else if peer.resolved.is_none() {
                LinkOutcome::Unknown {
                    reason: format!("{} did not resolve", peer.label),
                }
            } else {
                match select_protocol(&persona.caps(), &peer.caps(), &peer.did) {
                    Ok(m) => LinkOutcome::Selected {
                        protocol: m.protocol,
                        peer_endpoint: m.peer_endpoint,
                    },
                    Err(_) => LinkOutcome::NoCommonProtocol {
                        ours: persona.caps().advertised(),
                        theirs: peer.caps().advertised(),
                    },
                }
            };
            links.push(Link {
                from: persona.label.clone(),
                to: peer.label.clone(),
                outcome,
            });
        }
    }
    links
}

/// Turn the map into the handful of sentences an operator acts on.
fn collect_notes(parties: &[Party], links: &[Link]) -> Vec<String> {
    let mut notes = Vec::new();

    for party in parties {
        if let Some(error) = &party.error {
            notes.push(format!(
                "{} ({}) did not resolve: {error}",
                party.label, party.did
            ));
            continue;
        }
        let Some(resolved) = &party.resolved else {
            continue;
        };
        if resolved.services.is_empty() {
            notes.push(format!(
                "{} publishes no service endpoints at all — nothing can route to it.",
                party.label
            ));
        } else if resolved.tsp_endpoint.is_none()
            && resolved.didcomm_endpoint.is_none()
            && party.role != Role::Mediator
        {
            notes.push(format!(
                "{} advertises no TSP or DIDComm transport (services present, but none of a \
                 recognised type) — it cannot be messaged.",
                party.label
            ));
        }
        for probe in &resolved.probes {
            if let Probe::Unreachable { url, error } = probe {
                notes.push(format!("{}: {url} is unreachable ({error}).", party.label));
            }
        }
    }

    for link in links {
        match &link.outcome {
            LinkOutcome::NoCommonProtocol { ours, theirs } => notes.push(format!(
                "{} and {} share no transport: we offer [{}], they offer [{}]. A message \
                 between them cannot be sent until one side adds the other's.",
                link.from,
                link.to,
                join_protocols(ours),
                join_protocols(theirs),
            )),
            LinkOutcome::Unknown { reason } => notes.push(format!(
                "{} → {}: transport could not be determined ({reason}).",
                link.from, link.to
            )),
            LinkOutcome::Selected { .. } => {}
        }
    }

    // Split mediators are legal and often deliberate, but they are also the
    // thing an operator most often does not realise is true of their
    // deployment — so it is stated, not warned about.
    let mediators: BTreeSet<&str> = parties
        .iter()
        .filter(|p| p.role == Role::Mediator)
        .map(|p| p.did.as_str())
        .collect();
    if mediators.len() > 1 {
        notes.push(format!(
            "{} distinct mediators are in play; messages cross between them. This is \
             supported, but it means a delivery problem can live in either.",
            mediators.len()
        ));
    }

    notes
}

fn join_protocols(protocols: &[Protocol]) -> String {
    if protocols.is_empty() {
        return "none".to_string();
    }
    protocols
        .iter()
        .map(|p| p.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn resolved_party(role: Role, label: &str, did: &str, doc: &Value) -> Party {
        let caps = ServiceCapabilities::from_did_document(doc);
        Party {
            role,
            label: label.to_string(),
            did: did.to_string(),
            resolved: Some(Resolved {
                services: service_entries(doc),
                tsp_endpoint: caps.tsp,
                didcomm_endpoint: caps.didcomm,
                rest_endpoint: caps.rest,
                probes: Vec::new(),
            }),
            error: None,
        }
    }

    /// The shape a persona minted by the VTA's webvh server actually publishes —
    /// taken from a real document, including the `#vta-didcomm` id, because the
    /// matcher must key on `type` and never on the id fragment.
    fn persona_doc(mediator: &str) -> Value {
        json!({
            "service": [
                {
                    "id": "did:webvh:scid:example:persona#tsp",
                    "type": "TSPTransport",
                    "serviceEndpoint": mediator,
                },
                {
                    "id": "did:webvh:scid:example:persona#vta-didcomm",
                    "type": "DIDCommMessaging",
                    "serviceEndpoint": [{ "uri": mediator, "accept": ["didcomm/v2"] }],
                },
            ]
        })
    }

    #[test]
    fn services_are_read_verbatim_including_unrecognised_types() {
        let doc = json!({
            "service": [
                { "id": "#tsp", "type": "TSPTransport", "serviceEndpoint": "did:webvh:m" },
                { "id": "#odd", "type": "SomeFutureTransport", "serviceEndpoint": "https://x/y" },
            ]
        });
        let entries = service_entries(&doc);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].types, vec!["SomeFutureTransport".to_string()]);
        assert_eq!(
            entries[1].endpoint, "https://x/y",
            "an unrecognised transport must still be shown — a party that publishes \
             one looks empty through ServiceCapabilities alone, and telling that \
             apart from publishing nothing is the point of the map"
        );
    }

    /// DID-Core allows `type` as an array and `serviceEndpoint` in three shapes.
    #[test]
    fn endpoint_and_type_shapes_are_all_read() {
        assert_eq!(endpoint_uri(&json!("https://a")), Some("https://a".into()));
        assert_eq!(
            endpoint_uri(&json!({"uri": "did:webvh:m"})),
            Some("did:webvh:m".into())
        );
        assert_eq!(
            endpoint_uri(&json!([{"uri": "did:webvh:m"}])),
            Some("did:webvh:m".into())
        );

        let doc = json!({
            "service": [{
                "id": "#both", "type": ["DIDCommMessaging", "Other"],
                "serviceEndpoint": [{ "uri": "did:webvh:m" }],
            }]
        });
        assert_eq!(service_entries(&doc)[0].types.len(), 2);
    }

    /// Both sides on TSP: the negotiated protocol is TSP, and the endpoint is
    /// the *peer's* mediator (the hop a routed send seals to), not ours.
    #[test]
    fn a_shared_transport_negotiates_and_names_the_peer_mediator() {
        let parties = vec![
            resolved_party(
                Role::Persona,
                "persona",
                "did:webvh:p",
                &persona_doc("did:webvh:our-mediator"),
            ),
            resolved_party(
                Role::Vtc,
                "VTC",
                "did:webvh:v",
                &persona_doc("did:webvh:their-mediator"),
            ),
        ];
        let links = negotiate_links(&parties);
        assert_eq!(links.len(), 1);
        match &links[0].outcome {
            LinkOutcome::Selected {
                protocol,
                peer_endpoint,
            } => {
                assert_eq!(*protocol, Protocol::Tsp, "TSP outranks DIDComm");
                assert_eq!(peer_endpoint, "did:webvh:their-mediator");
            }
            other => panic!("expected a selected protocol, got {other:?}"),
        }
    }

    /// The case worth catching before a send: no intersection. Both sides'
    /// advertised sets must survive into the note, because "add TSP" and "add
    /// DIDComm" are different instructions to different operators.
    #[test]
    fn a_disjoint_pair_reports_both_sides() {
        let tsp_only = json!({
            "service": [{ "id": "#tsp", "type": "TSPTransport", "serviceEndpoint": "did:webvh:m1" }]
        });
        let didcomm_only = json!({
            "service": [{
                "id": "#dc", "type": "DIDCommMessaging",
                "serviceEndpoint": [{ "uri": "did:webvh:m2" }],
            }]
        });
        let parties = vec![
            resolved_party(Role::Persona, "persona", "did:webvh:p", &tsp_only),
            resolved_party(Role::Vtc, "VTC", "did:webvh:v", &didcomm_only),
        ];
        let links = negotiate_links(&parties);
        assert!(matches!(
            links[0].outcome,
            LinkOutcome::NoCommonProtocol { .. }
        ));

        let notes = collect_notes(&parties, &links);
        let note = notes
            .iter()
            .find(|n| n.contains("share no transport"))
            .expect("a disjoint pair must produce a note");
        assert!(note.contains("tsp"), "our side must be named: {note}");
        assert!(note.contains("didcomm"), "their side must be named: {note}");
        assert!(
            !HealthReport {
                parties,
                links,
                notes,
            }
            .is_healthy()
        );
    }

    /// An unresolvable party is a dead end, not a negotiation failure — the note
    /// must say which DID failed and why, since that is the whole diagnosis.
    #[test]
    fn an_unresolvable_peer_is_named_with_its_reason() {
        let parties = vec![
            resolved_party(
                Role::Persona,
                "persona",
                "did:webvh:p",
                &persona_doc("did:webvh:m"),
            ),
            Party {
                role: Role::Vtc,
                label: "VTC".into(),
                did: "did:webvh:missing".into(),
                resolved: None,
                error: Some("404 fetching did.jsonl".into()),
            },
        ];
        let links = negotiate_links(&parties);
        assert!(matches!(links[0].outcome, LinkOutcome::Unknown { .. }));

        let notes = collect_notes(&parties, &links);
        assert!(
            notes
                .iter()
                .any(|n| n.contains("did:webvh:missing") && n.contains("404")),
            "the failing DID and its reason must both appear: {notes:?}"
        );
        assert!(
            !HealthReport {
                parties,
                links,
                notes
            }
            .is_healthy()
        );
    }

    /// A mediator carrying both transports for a party must say so, and one
    /// shared by two parties must be resolved once and name both.
    ///
    /// Labelling it after the first protocol and the first party to mention it
    /// hid exactly the two facts the map exists to show: that the host carries
    /// both legs, and who else is behind it.
    #[test]
    fn a_shared_mediator_names_every_party_and_transport() {
        let parties = vec![
            resolved_party(
                Role::Persona,
                "persona joy-ahead",
                "did:webvh:p",
                &persona_doc("did:webvh:shared"),
            ),
            resolved_party(
                Role::Vtc,
                "VTC acme",
                "did:webvh:v",
                &json!({
                    "service": [{
                        "id": "#dc", "type": "DIDCommMessaging",
                        "serviceEndpoint": [{ "uri": "did:webvh:shared" }],
                    }]
                }),
            ),
        ];

        let refs = mediator_references(&parties);
        assert_eq!(refs.len(), 1, "one host, resolved once: {refs:?}");
        let label = &refs["did:webvh:shared"];
        assert_eq!(
            label, "persona joy-ahead (TSP, DIDComm), VTC acme (DIDComm)",
            "both parties, and TSP before DIDComm (negotiation order, not \
             alphabetical): {label}"
        );
    }

    /// A URL endpoint is the transport itself, not a mediator to follow.
    #[test]
    fn a_url_endpoint_is_not_followed_as_a_mediator() {
        let parties = vec![resolved_party(
            Role::Mediator,
            "mediator",
            "did:webvh:m",
            &json!({
                "service": [{
                    "id": "#tsp", "type": "TSPTransport",
                    "serviceEndpoint": "https://mediator.example/mediator/v1",
                }]
            }),
        )];
        assert!(
            mediator_references(&parties).is_empty(),
            "following a transport URL as a DID would resolve nothing and add a \
             bogus party to the map"
        );
    }

    /// Two mediators is legal. It must be *stated* (it is the thing operators
    /// most often don't know is true of their deployment) but must not make the
    /// report unhealthy.
    #[test]
    fn split_mediators_are_reported_without_being_called_a_fault() {
        let parties = vec![
            resolved_party(
                Role::Persona,
                "persona",
                "did:webvh:p",
                &persona_doc("did:webvh:m1"),
            ),
            resolved_party(
                Role::Vtc,
                "VTC",
                "did:webvh:v",
                &persona_doc("did:webvh:m2"),
            ),
            resolved_party(
                Role::Mediator,
                "mediator of persona",
                "did:webvh:m1",
                &json!({}),
            ),
            resolved_party(
                Role::Mediator,
                "mediator of VTC",
                "did:webvh:m2",
                &json!({}),
            ),
        ];
        let links = negotiate_links(&parties);
        let notes = collect_notes(&parties, &links);
        assert!(
            notes.iter().any(|n| n.contains("distinct mediators")),
            "split mediators must be surfaced: {notes:?}"
        );
        assert!(
            HealthReport {
                parties,
                links,
                notes
            }
            .is_healthy(),
            "two mediators is a supported topology, not a failure"
        );
    }

    /// A mediator with no recognised transport is normal (its own document
    /// carries a URL, not a mediator DID), so it must not draw the
    /// "cannot be messaged" note that a VTC or persona would.
    #[test]
    fn a_mediator_is_not_faulted_for_advertising_no_mediator() {
        let mediator_doc = json!({
            "service": [{
                "id": "#tsp", "type": "TSPTransport",
                "serviceEndpoint": "https://mediator.example/mediator/v1",
            }]
        });
        let parties = vec![resolved_party(
            Role::Mediator,
            "mediator of persona",
            "did:webvh:m",
            &mediator_doc,
        )];
        let notes = collect_notes(&parties, &[]);
        assert!(
            !notes.iter().any(|n| n.contains("cannot be messaged")),
            "a mediator publishing a transport URL is healthy: {notes:?}"
        );
    }
}
