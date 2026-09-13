use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    time::Duration,
};

use chrono::{DateTime, Utc};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::{
    live_loader::reseal_live_projection, load_live_run_at, load_operational_conditions_at,
    static_ui::StaticUi, CaseworkLiveRunIndexEntryV1, CaseworkLiveRunIndexV1,
    CaseworkOperationalConditionIndexEntryV1, CaseworkOperationalConditionIndexV1, LoadedLiveRun,
    LoadedOperationalCondition, LoadedRun, RunIndexEntryV1, RunIndexV1, RunSummaryV1,
    CASEWORK_LIVE_RUN_INDEX_SCHEMA_V1, CASEWORK_OPERATIONAL_CONDITION_INDEX_SCHEMA_V1,
};

const MAX_REQUEST_LINE_BYTES: u64 = 8 * 1024;
const MAX_HEADER_LINES: usize = 100;

#[derive(Clone, Debug)]
pub struct Api {
    runs: BTreeMap<String, LoadedRun>,
    live_sources: BTreeMap<String, LiveRunSource>,
    operational_conditions: BTreeMap<String, LoadedOperationalCondition>,
    evaluated_at: Option<DateTime<Utc>>,
    static_ui: Option<StaticUi>,
}

#[derive(Clone, Debug)]
pub struct LiveRunSource {
    pub navigation_id: String,
    pub store_path: PathBuf,
    pub run_id: String,
}

#[derive(Clone, Debug)]
pub struct Response {
    pub status: u16,
    pub reason: &'static str,
    pub content_type: &'static str,
    pub etag: Option<String>,
    pub allow: &'static str,
    pub body: Vec<u8>,
}

impl Api {
    pub fn new(runs: BTreeMap<String, LoadedRun>) -> Self {
        Self {
            runs,
            live_sources: BTreeMap::new(),
            operational_conditions: BTreeMap::new(),
            evaluated_at: None,
            static_ui: None,
        }
    }

    pub fn with_live_sources(
        mut self,
        sources: Vec<(PathBuf, String)>,
        evaluated_at: Option<DateTime<Utc>>,
    ) -> Result<Self, String> {
        self.evaluated_at = evaluated_at;
        let now = self.evaluation_time();
        for (store_path, run_id) in sources {
            let loaded =
                load_live_run_at(&store_path, &run_id, now).map_err(|error| error.to_string())?;
            let navigation_id = loaded.projection.navigation_id.clone();
            if self
                .live_sources
                .insert(
                    navigation_id.clone(),
                    LiveRunSource {
                        navigation_id: navigation_id.clone(),
                        store_path,
                        run_id,
                    },
                )
                .is_some()
            {
                return Err(format!("duplicate live run navigation id {navigation_id}"));
            }
        }
        Ok(self)
    }
    pub fn with_operational_conditions(mut self, directories: &[PathBuf]) -> Result<Self, String> {
        self.operational_conditions =
            load_operational_conditions_at(directories).map_err(|error| error.to_string())?;
        Ok(self)
    }

    pub fn with_static_ui(mut self, static_ui: StaticUi) -> Self {
        self.static_ui = Some(static_ui);
        self
    }

    pub fn response(&self, method: &str, path: &str) -> Response {
        let operational_family = is_operational_condition_route(path);
        if method != "GET" && !(method == "HEAD" && operational_family) {
            return Response::text(405, "Method Not Allowed", b"method not allowed\n".to_vec());
        }
        if path == "/healthz" {
            return Response::json(
                200,
                "OK",
                br#"{"status":"ok"}"#.to_vec(),
                Some(quoted_etag("healthz")),
            );
        }
        if path == "/api/v1/runs" {
            let index = RunIndexV1 {
                schema: "nightshift.casework-run-index/v1".to_owned(),
                runs: self.runs.values().map(index_entry).collect(),
            };
            return json_response(&index, None);
        }
        if path == "/api/v1/active-runs" {
            let mut runs = Vec::with_capacity(self.live_sources.len());
            for source in self.live_sources.values() {
                let loaded = match self.load_live(source) {
                    Ok(loaded) => loaded,
                    Err(response) => return response,
                };
                runs.push(live_index_entry(&loaded));
            }
            return json_response(
                &CaseworkLiveRunIndexV1 {
                    schema: CASEWORK_LIVE_RUN_INDEX_SCHEMA_V1.to_owned(),
                    runs,
                },
                None,
            );
        }
        if path == "/api/v1/operational-conditions" {
            let index = CaseworkOperationalConditionIndexV1 {
                schema: CASEWORK_OPERATIONAL_CONDITION_INDEX_SCHEMA_V1.to_owned(),
                conditions: self
                    .operational_conditions
                    .values()
                    .map(operational_index_entry)
                    .collect(),
            };
            return operational_json_response(&index, None);
        }
        if !path.starts_with("/api/") {
            if let Some(asset) = self
                .static_ui
                .as_ref()
                .and_then(|ui| ui.response_asset(path))
            {
                return Response {
                    status: 200,
                    reason: "OK",
                    content_type: asset.content_type,
                    etag: Some(asset.etag.clone()),
                    allow: "GET",
                    body: asset.bytes.clone(),
                };
            }
        }
        if let Some((navigation_id, suffix)) = parse_operational_condition_path(path) {
            let Some(condition) = self.operational_conditions.get(navigation_id) else {
                return Response::text(404, "Not Found", b"not found\n".to_vec()).with_head();
            };
            return operational_response(condition, suffix);
        }
        if let Some((navigation_id, suffix)) = parse_live_run_path(path) {
            let Some(source) = self.live_sources.get(navigation_id) else {
                return Response::text(404, "Not Found", b"not found\n".to_vec());
            };
            let loaded = match self.load_live(source) {
                Ok(loaded) => loaded,
                Err(response) => return response,
            };
            return live_response(&loaded, suffix);
        }
        let Some((run_id, suffix)) = parse_run_path(path) else {
            return Response::text(404, "Not Found", b"not found\n".to_vec());
        };
        let Some(run) = self.runs.get(run_id) else {
            return Response::text(404, "Not Found", b"not found\n".to_vec());
        };
        match suffix {
            "" => json_response(
                &run.projection,
                Some(quoted_etag(&run.projection.projection_digest)),
            ),
            "/raw/packet" => Response::json(
                200,
                "OK",
                run.packet_bytes.clone(),
                Some(quoted_etag(&run.projection.packet.source_bytes_digest)),
            ),
            "/raw/receipts" => Response::json(
                200,
                "OK",
                run.receipt_bytes.clone(),
                Some(quoted_etag(&run.projection.receipts.source_bytes_digest)),
            ),
            _ => Response::text(404, "Not Found", b"not found\n".to_vec()),
        }
    }

    fn evaluation_time(&self) -> DateTime<Utc> {
        self.evaluated_at.unwrap_or_else(Utc::now)
    }

    fn load_live(&self, source: &LiveRunSource) -> Result<LoadedLiveRun, Response> {
        let mut loaded =
            load_live_run_at(&source.store_path, &source.run_id, self.evaluation_time()).map_err(
                |error| {
                    Response::text(500, "Internal Server Error", {
                        let _ = error;
                        b"live read refused\n".to_vec()
                    })
                },
            )?;
        loaded.projection.sealed_case_run_id =
            loaded
                .final_snapshot_bytes
                .as_ref()
                .and_then(|final_bytes| {
                    self.runs
                        .values()
                        .find(|sealed| {
                            sealed.projection.packet.packet_digest
                                == loaded.projection.packet.packet_digest
                                && sealed.receipt_bytes == *final_bytes
                        })
                        .map(|sealed| sealed.projection.run_id.clone())
                });
        reseal_live_projection(&mut loaded.projection).map_err(|_| {
            Response::text(
                500,
                "Internal Server Error",
                b"live projection refused\n".to_vec(),
            )
        })?;
        Ok(loaded)
    }
}

impl Response {
    fn json(status: u16, reason: &'static str, body: Vec<u8>, etag: Option<String>) -> Self {
        Self {
            status,
            reason,
            content_type: "application/json",
            etag,
            allow: "GET",
            body,
        }
    }

    fn text(status: u16, reason: &'static str, body: Vec<u8>) -> Self {
        Self {
            status,
            reason,
            content_type: "text/plain; charset=utf-8",
            etag: None,
            allow: "GET",
            body,
        }
    }

    fn binary(body: Vec<u8>, etag: String) -> Self {
        Self {
            status: 200,
            reason: "OK",
            content_type: "application/octet-stream",
            etag: Some(quoted_etag(&etag)),
            allow: "GET",
            body,
        }
    }

    fn with_head(mut self) -> Self {
        self.allow = "GET, HEAD";
        self
    }
}

pub fn bind_loopback(address: SocketAddr) -> std::io::Result<TcpListener> {
    if !address.ip().is_loopback() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "nightshift-casework refuses non-loopback binds",
        ));
    }
    TcpListener::bind(address)
}

pub fn serve(listener: TcpListener, api: Api) -> std::io::Result<()> {
    let local = listener.local_addr()?;
    if !local.ip().is_loopback() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "listener is not bound to loopback",
        ));
    }
    for stream in listener.incoming() {
        let mut stream = stream?;
        if let Err(error) = handle_stream(&mut stream, &api) {
            eprintln!("nightshift-casework request error: {error}");
        }
    }
    Ok(())
}

fn handle_stream(stream: &mut TcpStream, api: &Api) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader
        .by_ref()
        .take(MAX_REQUEST_LINE_BYTES)
        .read_line(&mut request_line)?;
    let mut parts = request_line.trim_end_matches(['\r', '\n']).split(' ');
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    let version = parts.next().unwrap_or("");
    let request_valid = !method.is_empty()
        && path.starts_with('/')
        && (version == "HTTP/1.0" || version == "HTTP/1.1")
        && parts.next().is_none();

    let mut headers_complete = false;
    for _ in 0..MAX_HEADER_LINES {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        if line == "\r\n" || line == "\n" {
            headers_complete = true;
            break;
        }
    }
    let response = if request_valid && headers_complete {
        api.response(method, path)
    } else {
        Response::text(400, "Bad Request", b"bad request\n".to_vec())
    };
    let head_only = method == "HEAD" && response.allow == "GET, HEAD";
    write_response(stream, &response, head_only)
}

fn write_response(
    stream: &mut TcpStream,
    response: &Response,
    head_only: bool,
) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\n",
        response.status,
        response.reason,
        response.content_type,
        response.body.len()
    )?;
    if let Some(etag) = &response.etag {
        write!(stream, "ETag: {etag}\r\n")?;
    }
    write!(
        stream,
        "Allow: {}\r\nCache-Control: private, max-age=0, must-revalidate\r\nContent-Security-Policy: default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'\r\nCross-Origin-Opener-Policy: same-origin\r\nCross-Origin-Resource-Policy: same-origin\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nConnection: close\r\n\r\n",
        response.allow
    )?;
    if !head_only {
        stream.write_all(&response.body)?;
    }
    stream.flush()
}

fn parse_run_path(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix("/api/v1/runs/")?;
    let (run_id, suffix) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, ""),
    };
    if run_id.len() != 64
        || !run_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return None;
    }
    Some((run_id, suffix))
}

fn parse_live_run_path(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix("/api/v1/active-runs/")?;
    let (navigation_id, suffix) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, ""),
    };
    if !valid_digest_id(navigation_id) {
        return None;
    }
    Some((navigation_id, suffix))
}
fn is_operational_condition_route(path: &str) -> bool {
    if path == "/api/v1/operational-conditions" {
        return true;
    }
    parse_operational_condition_path(path).is_some_and(|(_, suffix)| {
        matches!(
            suffix,
            "" | "/raw/monitor" | "/raw/nq" | "/raw/lineage" | "/raw/profile" | "/raw/evaluation"
        )
    })
}

fn parse_operational_condition_path(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix("/api/v1/operational-conditions/")?;
    let (navigation_id, suffix) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, ""),
    };
    if !valid_digest_id(navigation_id) {
        return None;
    }
    Some((navigation_id, suffix))
}

fn valid_digest_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn live_index_entry(run: &LoadedLiveRun) -> CaseworkLiveRunIndexEntryV1 {
    CaseworkLiveRunIndexEntryV1 {
        navigation_id: run.projection.navigation_id.clone(),
        run_id: run.projection.run_id.clone(),
        projection_digest: run.projection.projection_digest.clone(),
        packet_id: run.projection.packet.packet_id.clone(),
        packet_digest: run.projection.packet.packet_digest.clone(),
        lifecycle: run.projection.foreman.lifecycle.clone(),
        sealed_case_run_id: run.projection.sealed_case_run_id.clone(),
        scheduler_state_counts: run.projection.foreman.scheduler_state_counts.clone(),
    }
}

fn live_response(run: &LoadedLiveRun, suffix: &str) -> Response {
    match suffix {
        "" => json_response(
            &run.projection,
            Some(quoted_etag(&run.projection.projection_digest)),
        ),
        "/provider-execution" => json_response(
            &run.provider_execution,
            Some(quoted_etag(&run.provider_execution.projection_digest)),
        ),
        "/events" => json_response(&run.projection.events, None),
        "/raw/packet" => Response::json(
            200,
            "OK",
            run.packet_bytes.clone(),
            Some(quoted_etag(&run.projection.raw_sources.packet_sha256)),
        ),
        "/raw/admission" => Response::json(
            200,
            "OK",
            run.admission_bytes.clone(),
            Some(quoted_etag(&run.projection.raw_sources.admission_sha256)),
        ),
        "/raw/profile" => Response::json(
            200,
            "OK",
            run.profile_bytes.clone(),
            Some(quoted_etag(&run.projection.raw_sources.profile_sha256)),
        ),
        "/raw/foreman-journal" => Response::binary(
            run.journal_framing_bytes.clone(),
            run.projection.raw_sources.journal_framing_sha256.clone(),
        ),
        "/raw/accepted-receipts" => Response::binary(
            run.accepted_receipts_framing_bytes.clone(),
            run.projection
                .raw_sources
                .accepted_receipts_framing_sha256
                .clone(),
        ),
        "/raw/final" => match (
            &run.final_snapshot_bytes,
            &run.projection.raw_sources.final_snapshot_sha256,
        ) {
            (Some(bytes), Some(digest)) => {
                Response::json(200, "OK", bytes.clone(), Some(quoted_etag(digest)))
            }
            _ => Response::text(404, "Not Found", b"final snapshot absent\n".to_vec()),
        },
        _ => {
            let Some(sequence) = suffix
                .strip_prefix("/events/")
                .and_then(|value| value.strip_suffix("/raw"))
                .and_then(|value| value.parse::<u64>().ok())
            else {
                return Response::text(404, "Not Found", b"not found\n".to_vec());
            };
            match run.event_bytes.get(&sequence) {
                Some(bytes) => Response::json(
                    200,
                    "OK",
                    bytes.clone(),
                    Some(quoted_etag(&format!("sha256:{:x}", Sha256::digest(bytes)))),
                ),
                None => Response::text(404, "Not Found", b"not found\n".to_vec()),
            }
        }
    }
}
fn operational_index_entry(
    condition: &LoadedOperationalCondition,
) -> CaseworkOperationalConditionIndexEntryV1 {
    let projection = &condition.projection;
    CaseworkOperationalConditionIndexEntryV1 {
        navigation_id: projection.navigation_id.clone(),
        projection_digest: projection.projection_digest.clone(),
        lineage_id: projection.lineage.lineage_id.clone(),
        evaluation_id: projection.evaluation.evaluation_id.clone(),
        subject_kind: projection.subject.kind,
        subject_namespace: projection.subject.namespace.clone(),
        subject_identity_digest: projection.subject_identity_digest.clone(),
        disposition: projection.evaluation.disposition,
        reobservation_trigger: projection.evaluation.reobservation_trigger,
        evaluated_at: projection.evaluation.evaluated_at.clone(),
        question_count: projection.questions.len(),
    }
}

fn operational_response(condition: &LoadedOperationalCondition, suffix: &str) -> Response {
    let projection = &condition.projection;
    match suffix {
        "" => {
            operational_json_response(projection, Some(quoted_etag(&projection.projection_digest)))
        }
        "/raw/monitor" => operational_raw_response(
            &condition.monitor_bytes,
            &projection.raw_sources.monitor.exact_bytes_sha256,
        ),
        "/raw/nq" => operational_raw_response(
            &condition.nq_bytes,
            &projection.raw_sources.nq.exact_bytes_sha256,
        ),
        "/raw/lineage" => operational_raw_response(
            &condition.lineage_bytes,
            &projection.raw_sources.lineage.exact_bytes_sha256,
        ),
        "/raw/profile" => operational_raw_response(
            &condition.profile_bytes,
            &projection.raw_sources.profile.exact_bytes_sha256,
        ),
        "/raw/evaluation" => operational_raw_response(
            &condition.evaluation_bytes,
            &projection.raw_sources.evaluation.exact_bytes_sha256,
        ),
        _ => Response::text(404, "Not Found", b"not found\n".to_vec()).with_head(),
    }
}

fn operational_raw_response(bytes: &[u8], digest: &str) -> Response {
    Response::json(200, "OK", bytes.to_vec(), Some(quoted_etag(digest))).with_head()
}

fn index_entry(run: &LoadedRun) -> RunIndexEntryV1 {
    let projection = &run.projection;
    RunIndexEntryV1 {
        run_id: projection.run_id.clone(),
        projection_digest: projection.projection_digest.clone(),
        packet_id: projection.packet.packet_id.clone(),
        packet_digest: projection.packet.packet_digest.clone(),
        receipt_updated_at: projection.receipts.updated_at.clone(),
        summary: RunSummaryV1 {
            work_item_count: projection.summary.work_item_count,
            state_counts: projection.summary.state_counts.clone(),
            unrecognized_state_count: projection.summary.unrecognized_state_count,
            human_question_count: projection.summary.human_question_count,
            packet_custody_discrepancy_count: projection.summary.packet_custody_discrepancy_count,
        },
        packet_integrity: projection.packet.integrity.clone(),
        packet_currentness_at_receipt_snapshot: projection
            .packet
            .currentness_at_receipt_snapshot
            .clone(),
        packet_currentness_now: projection.packet.currentness_now.clone(),
    }
}

fn json_response(value: &impl Serialize, etag: Option<String>) -> Response {
    match serde_json::to_vec(value) {
        Ok(body) => {
            let etag = etag.or_else(|| Some(quoted_etag(&format!("{:x}", Sha256::digest(&body)))));
            Response::json(200, "OK", body, etag)
        }
        Err(_) => Response::text(
            500,
            "Internal Server Error",
            b"serialization failed\n".to_vec(),
        ),
    }
}
fn operational_json_response(value: &impl Serialize, etag: Option<String>) -> Response {
    json_response(value, etag).with_head()
}

fn quoted_etag(identity: &str) -> String {
    format!(
        "\"{}\"",
        identity.strip_prefix("sha256:").unwrap_or(identity)
    )
}
#[cfg(test)]
mod wire_tests {
    use std::{
        io::{Read, Write},
        net::TcpStream,
        path::Path,
        thread,
    };

    use chrono::{TimeZone, Utc};

    use super::*;
    use crate::live_loader::test_support::{
        closed_fixture, fixture as live_fixture, instant as live_instant,
    };
    use crate::load_runs_at;

    const GOLDEN: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../qualification/nightshift-packet-v1/velvet-orrery"
    );

    fn api() -> (Api, String, Vec<u8>) {
        let runs = load_runs_at(
            &[Path::new(GOLDEN).to_path_buf()],
            Utc.with_ymd_and_hms(2026, 8, 31, 0, 0, 0).unwrap(),
        )
        .unwrap();
        let run = runs.values().next().unwrap();
        (
            Api::new(runs.clone()),
            run.projection.run_id.clone(),
            run.packet_bytes.clone(),
        )
    }

    fn wire_request(api: Api, request: &[u8]) -> Vec<u8> {
        let listener = bind_loopback("127.0.0.1:0".parse().unwrap()).unwrap();
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            handle_stream(&mut stream, &api).unwrap();
        });
        let mut stream = TcpStream::connect(address).unwrap();
        stream.write_all(request).unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();
        worker.join().unwrap();
        response
    }

    #[test]
    fn bounded_wire_requests_preserve_headers_raw_bytes_and_405() {
        let (api, run_id, packet) = api();
        let request =
            format!("GET /api/v1/runs/{run_id}/raw/packet HTTP/1.1\r\nHost: localhost\r\n\r\n");
        let response = wire_request(api.clone(), request.as_bytes());
        let boundary = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap()
            + 4;
        let headers = std::str::from_utf8(&response[..boundary]).unwrap();
        assert!(headers.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(headers.contains("\r\nETag: "));
        assert!(headers.contains("\r\nContent-Security-Policy: "));
        assert!(headers.contains("\r\nCross-Origin-Resource-Policy: same-origin\r\n"));
        assert!(headers.contains("\r\nX-Content-Type-Options: nosniff\r\n"));
        assert!(!headers
            .to_ascii_lowercase()
            .contains("access-control-allow-origin"));
        assert_eq!(&response[boundary..], packet);

        for method in ["POST", "PUT", "PATCH", "DELETE"] {
            let request =
                format!("{method} /api/v1/runs/{run_id} HTTP/1.1\r\nHost: localhost\r\n\r\n");
            let response = wire_request(api.clone(), request.as_bytes());
            assert!(response.starts_with(b"HTTP/1.1 405 Method Not Allowed\r\n"));
        }
    }

    #[test]
    fn registered_live_routes_are_query_only_exact_and_navigation_bound() {
        let (_directory, store_path, run_id) = live_fixture();
        let loaded = load_live_run_at(&store_path, &run_id, live_instant()).unwrap();
        let navigation_id = loaded.projection.navigation_id.clone();
        let api = Api::new(BTreeMap::new())
            .with_live_sources(vec![(store_path, run_id)], Some(live_instant()))
            .unwrap();

        let detail = api.response("GET", &format!("/api/v1/active-runs/{navigation_id}"));
        assert_eq!(detail.status, 200);
        let projection: crate::CaseworkLiveRunV1 = serde_json::from_slice(&detail.body).unwrap();
        assert_eq!(projection.navigation_id, navigation_id);

        let execution = api.response(
            "GET",
            &format!("/api/v1/active-runs/{navigation_id}/provider-execution"),
        );
        assert_eq!(execution.status, 200);
        let execution: crate::CaseworkLiveProviderExecutionV1 =
            serde_json::from_slice(&execution.body).unwrap();
        assert_eq!(execution.status, "NOT_RECORDED_BY_FOREMAN");
        assert_eq!(
            execution.projection_digest,
            loaded.provider_execution.projection_digest
        );

        let packet = api.response(
            "GET",
            &format!("/api/v1/active-runs/{navigation_id}/raw/packet"),
        );
        assert_eq!(packet.status, 200);
        assert_eq!(packet.body, loaded.packet_bytes);
        let receipts = api.response(
            "GET",
            &format!("/api/v1/active-runs/{navigation_id}/raw/accepted-receipts"),
        );
        assert_eq!(receipts.status, 200);
        assert_eq!(receipts.body, loaded.accepted_receipts_framing_bytes);
        assert_eq!(
            api.response("GET", "/api/v1/active-runs/not-a-navigation-id")
                .status,
            404
        );
        for method in ["HEAD", "POST", "PUT", "PATCH", "DELETE"] {
            assert_eq!(
                api.response(
                    method,
                    &format!("/api/v1/active-runs/{navigation_id}/provider-execution"),
                )
                .status,
                405
            );
        }
    }

    #[test]
    fn closed_live_history_links_only_to_exact_packet_and_final_bytes() {
        let (_store_directory, store_path, run_id, final_bytes) = closed_fixture();
        let loaded = load_live_run_at(&store_path, &run_id, live_instant()).unwrap();
        assert!(loaded
            .accepted_receipts_framing_bytes
            .starts_with(crate::FOREMAN_ACCEPTED_RECEIPTS_FRAMING_V1));

        let case_directory = tempfile::tempdir().unwrap();
        std::fs::write(
            case_directory.path().join("packet.v1.json"),
            &loaded.packet_bytes,
        )
        .unwrap();
        std::fs::write(
            case_directory.path().join("run-receipts.v1.json"),
            &final_bytes,
        )
        .unwrap();
        let sealed_runs =
            load_runs_at(&[case_directory.path().to_path_buf()], live_instant()).unwrap();
        let sealed_run_id = sealed_runs
            .values()
            .next()
            .unwrap()
            .projection
            .run_id
            .clone();
        let navigation_id = loaded.projection.navigation_id;
        let api = Api::new(sealed_runs)
            .with_live_sources(
                vec![(store_path.clone(), run_id.clone())],
                Some(live_instant()),
            )
            .unwrap();
        let response = api.response("GET", &format!("/api/v1/active-runs/{navigation_id}"));
        let projection: crate::CaseworkLiveRunV1 = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(
            projection.sealed_case_run_id.as_deref(),
            Some(sealed_run_id.as_str())
        );
        let final_response = api.response(
            "GET",
            &format!("/api/v1/active-runs/{navigation_id}/raw/final"),
        );
        assert_eq!(final_response.status, 200);
        assert_eq!(final_response.body, final_bytes);
        let (&sequence, event_bytes) = loaded.event_bytes.iter().next().unwrap();
        let event_response = api.response(
            "GET",
            &format!("/api/v1/active-runs/{navigation_id}/events/{sequence}/raw"),
        );
        assert_eq!(event_response.status, 200);
        assert_eq!(&event_response.body, event_bytes);

        let mut substituted_runs = api.runs.clone();
        substituted_runs
            .values_mut()
            .next()
            .unwrap()
            .receipt_bytes
            .push(b' ');
        let substituted = Api::new(substituted_runs)
            .with_live_sources(vec![(store_path, run_id)], Some(live_instant()))
            .unwrap();
        let response = substituted.response("GET", &format!("/api/v1/active-runs/{navigation_id}"));
        let projection: crate::CaseworkLiveRunV1 = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(projection.sealed_case_run_id, None);
    }
    fn operational_api() -> (tempfile::TempDir, Api, String, [Vec<u8>; 5]) {
        const MONITOR: &[u8] = include_bytes!(
            "../../nightshiftd/tests/fixtures/operational_lineage/field-monitor.accepted.json"
        );
        const NQ: &[u8] = include_bytes!(
            "../../nightshiftd/tests/fixtures/operational_lineage/field-nq.accepted.json"
        );
        let temporary = tempfile::tempdir().unwrap();
        let condition = temporary.path().join("condition");
        std::fs::create_dir(&condition).unwrap();
        let admitted_at = Utc.with_ymd_and_hms(2026, 8, 30, 3, 0, 1).single().unwrap();
        let lineage = nightshiftd::operational_lineage::admit_operational_lineage(
            MONITOR,
            NQ,
            "input:field-vector",
            admitted_at,
            &[],
        )
        .unwrap()
        .0;
        let profile = nightshiftd::operational_lineage::ReobservationProfileV1 {
            profile_id: "profile:shift-api".into(),
            max_age_seconds: 60,
        };
        let evaluation = nightshiftd::operational_lineage::evaluate_reobservation(
            &lineage,
            &profile,
            admitted_at,
        )
        .unwrap();
        let lineage_bytes = serde_json::to_vec(&lineage).unwrap();
        let profile_bytes = serde_json::to_vec(&profile).unwrap();
        let evaluation_bytes = serde_json::to_vec(&evaluation).unwrap();
        for (name, bytes) in [
            ("monitor.v1.json", MONITOR),
            ("nq.v1.json", NQ),
            ("lineage.v1.json", lineage_bytes.as_slice()),
            ("profile.v1.json", profile_bytes.as_slice()),
            ("evaluation.v1.json", evaluation_bytes.as_slice()),
        ] {
            std::fs::write(condition.join(name), bytes).unwrap();
        }
        let api = Api::new(BTreeMap::new())
            .with_operational_conditions(std::slice::from_ref(&condition))
            .unwrap();
        let navigation_id = api.operational_conditions.keys().next().unwrap().clone();
        (
            temporary,
            api,
            navigation_id,
            [
                MONITOR.to_vec(),
                NQ.to_vec(),
                lineage_bytes,
                profile_bytes,
                evaluation_bytes,
            ],
        )
    }

    fn split_wire(response: &[u8]) -> (&[u8], &[u8]) {
        let boundary = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap()
            + 4;
        (&response[..boundary], &response[boundary..])
    }

    #[test]
    fn operational_routes_have_exact_get_head_parity_and_writes_remain_405() {
        let (_temporary, api, navigation_id, raw_bytes) = operational_api();
        let routes = [
            (
                format!("/api/v1/operational-conditions/{navigation_id}"),
                None,
            ),
            (
                format!("/api/v1/operational-conditions/{navigation_id}/raw/monitor"),
                Some(raw_bytes[0].as_slice()),
            ),
            (
                format!("/api/v1/operational-conditions/{navigation_id}/raw/nq"),
                Some(raw_bytes[1].as_slice()),
            ),
            (
                format!("/api/v1/operational-conditions/{navigation_id}/raw/lineage"),
                Some(raw_bytes[2].as_slice()),
            ),
            (
                format!("/api/v1/operational-conditions/{navigation_id}/raw/profile"),
                Some(raw_bytes[3].as_slice()),
            ),
            (
                format!("/api/v1/operational-conditions/{navigation_id}/raw/evaluation"),
                Some(raw_bytes[4].as_slice()),
            ),
        ];
        for (path, expected_raw) in routes {
            let get = wire_request(
                api.clone(),
                format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes(),
            );
            let head = wire_request(
                api.clone(),
                format!("HEAD {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes(),
            );
            let (get_headers, get_body) = split_wire(&get);
            let (head_headers, head_body) = split_wire(&head);
            assert_eq!(head_headers, get_headers, "{path}");
            assert!(head_body.is_empty(), "{path}");
            assert!(get_headers
                .windows(b"Allow: GET, HEAD\r\n".len())
                .any(|window| window == b"Allow: GET, HEAD\r\n"));
            if let Some(expected) = expected_raw {
                assert_eq!(get_body, expected, "{path}");
            }
        }

        let index_get = wire_request(
            api.clone(),
            b"GET /api/v1/operational-conditions HTTP/1.1\r\nHost: localhost\r\n\r\n",
        );
        let index_head = wire_request(
            api.clone(),
            b"HEAD /api/v1/operational-conditions HTTP/1.1\r\nHost: localhost\r\n\r\n",
        );
        assert_eq!(split_wire(&index_get).0, split_wire(&index_head).0);
        assert!(split_wire(&index_head).1.is_empty());

        for method in ["POST", "PUT", "PATCH", "DELETE"] {
            let response = wire_request(
                api.clone(),
                format!(
                    "{method} /api/v1/operational-conditions/{navigation_id} HTTP/1.1\r\nHost: localhost\r\n\r\n"
                )
                .as_bytes(),
            );
            assert!(response.starts_with(b"HTTP/1.1 405 Method Not Allowed\r\n"));
        }
        assert_eq!(
            api.response(
                "GET",
                &format!("/api/v1/operational-conditions/{navigation_id}/raw/monitor"),
            )
            .body,
            raw_bytes[0]
        );
        assert_eq!(
            api.response(
                "GET",
                &format!("/api/v1/operational-conditions/{navigation_id}/raw/monitor/extra"),
            )
            .status,
            404
        );
        assert_eq!(
            api.response(
                "HEAD",
                &format!("/api/v1/operational-conditions/{navigation_id}/raw/monitor/extra"),
            )
            .status,
            405
        );
        assert_eq!(
            api.response("GET", "/api/v1/operational-conditions/../raw/monitor")
                .status,
            404
        );

        let old_head = wire_request(api, b"HEAD /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n");
        let (headers, body) = split_wire(&old_head);
        assert!(headers.starts_with(b"HTTP/1.1 405 Method Not Allowed\r\n"));
        assert!(headers
            .windows(b"Allow: GET\r\n".len())
            .any(|window| window == b"Allow: GET\r\n"));
        assert_eq!(body, b"method not allowed\n");
    }
}
