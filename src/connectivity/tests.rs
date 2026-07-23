use super::probe::{connect_target, portal_outcome, sample_connection_quality};
use super::*;

#[test]
fn tcp_probe_distinguishes_reachable_from_closed() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let open = connect_target(&address.to_string(), Duration::from_millis(100));
    assert_eq!(open.status, StageStatus::Pass);
    drop(listener);
    let closed = connect_target(&address.to_string(), Duration::from_millis(100));
    assert_eq!(closed.status, StageStatus::Fail);
}

#[test]
fn malformed_target_is_a_failure_not_a_panic() {
    let result = connect_target("not-an-endpoint", Duration::from_millis(10));
    assert_eq!(result.status, StageStatus::Fail);
}

#[test]
fn portal_status_distinguishes_expected_sentinel_from_redirect() {
    assert_eq!(portal_outcome(Some(204), 204).0, StageStatus::Pass);
    assert_eq!(portal_outcome(Some(302), 204).0, StageStatus::Fail);
    assert_eq!(portal_outcome(None, 204).0, StageStatus::Fail);
}

#[test]
fn packet_quality_reports_connection_attempt_loss() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        for _ in 0..3 {
            listener.accept().unwrap();
        }
    });
    let quality = sample_connection_quality(&address.to_string(), Duration::from_secs(1), 3);
    server.join().unwrap();
    assert_eq!(quality.successes, 3);
    assert_eq!(quality.loss_percent, 0.0);
    assert!(quality.mean_latency_ms.is_some());
}
