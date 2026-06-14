//! Acceptance test from GUI_PLAN.md §5, driving the exact core functions the GUI's worker
//! thread calls (no egui in the loop). Runs at the REAL recommended Argon2id cost
//! (256 MiB / 3), so build with `--release` or it is very slow.
//!
//! 1. Create a 64k container, K from `next_prime_coprime8(419)`.
//! 2. Write two secrets under two passwords (re-randomize ON; the second write lists the
//!    first password as known and confirms all-keys).
//! 3. Read each back with its password — both round-trip.
//! 4. A wrong password → "no payload" (NotFound).

use azoth::next_prime_coprime8;
use azoth_gui::{create_container, read_payload, write_payload, Kdf, ReadOutcome};

/// Removes the temp container even if an assertion panics.
struct TempFile(String);
impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn found(outcome: ReadOutcome) -> Vec<u8> {
    match outcome {
        ReadOutcome::Found(pt) => pt.to_vec(),
        ReadOutcome::NotFound => panic!("expected a payload, got NotFound"),
    }
}

#[test]
fn acceptance_two_secrets_roundtrip() {
    let path = std::env::temp_dir()
        .join(format!("azoth_gui_accept_{}.bin", std::process::id()))
        .to_string_lossy()
        .into_owned();
    let _guard = TempFile(path.clone());

    let k = next_prime_coprime8(419);
    assert_eq!(k, 419, "419 is already an odd prime");
    let kdf = Kdf::RECOMMENDED;

    // 1. create a 64k container
    create_container(&path, 64 * 1024, k, kdf).expect("create");
    assert_eq!(
        std::fs::metadata(&path).expect("stat").len(),
        64 * 1024,
        "container should be exactly 64 KiB of bytes"
    );

    // 2. write two secrets, re-randomize ON, all-keys confirmed
    write_payload(&path, "alpha-pass", b"treaty at dawn", &[], k, kdf, true, true)
        .expect("first write");
    write_payload(
        &path,
        "beta-pass",
        b"pier 39",
        &["alpha-pass".to_string()],
        k,
        kdf,
        true,
        true,
    )
    .expect("second write");

    // 3. both round-trip
    assert_eq!(
        found(read_payload(&path, "alpha-pass", k, kdf).expect("read alpha")),
        b"treaty at dawn",
    );
    assert_eq!(
        found(read_payload(&path, "beta-pass", k, kdf).expect("read beta")),
        b"pier 39",
    );

    // 4. wrong password -> NotFound
    match read_payload(&path, "wrong-pass", k, kdf).expect("read wrong") {
        ReadOutcome::NotFound => {}
        ReadOutcome::Found(_) => panic!("a wrong password must not decrypt anything"),
    }
}

#[test]
fn rerandomize_requires_all_keys() {
    // The re-randomize default must refuse to run without the all-keys confirmation.
    // (write_payload reads the container first, like the CLI, so use a real one.)
    // create_container does no Argon2 work, so this test is fast.
    let path = std::env::temp_dir()
        .join(format!("azoth_gui_gate_{}.bin", std::process::id()))
        .to_string_lossy()
        .into_owned();
    let _guard = TempFile(path.clone());
    create_container(&path, 4096, 419, Kdf::RECOMMENDED).expect("create");

    let err = write_payload(
        &path, "pw", b"x", &[], 419, Kdf::RECOMMENDED, true, // re-randomize
        false, // but all-keys NOT confirmed
    )
    .expect_err("must refuse without all-keys");
    assert!(err.contains("destroys"), "got: {err}");
}
