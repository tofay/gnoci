//! Integration Tests for gnoci
use std::{
    fs::{self},
    path::{Path, PathBuf},
    process::Command,
};

use test_temp_dir::TestTempDir;

// Path to binary under test
const EXE: &str = env!("CARGO_BIN_EXE_gnoci");

fn is_ubuntu() -> bool {
    // Check if the /etc/os-release file contains "Ubuntu"
    let os_release = fs::read_to_string("/etc/os-release").unwrap_or_default();
    os_release.contains("ID=ubuntu")
}

fn curl_test() -> String {
    if is_ubuntu() {
        "curl-ubuntu".to_string()
    } else {
        "curl-almalinux".to_string()
    }
}

fn setup_test(fixture: &str) -> TestTempDir {
    // the test_temp_dir macro can't handle the integration test module path not containing ::,
    // so construct our own item path
    let out = test_temp_dir::TestTempDir::from_complete_item_path(&format!(
        "it::{}",
        std::thread::current().name().unwrap()
    ));
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/")
        .join(fixture);
    fs::copy(
        root.join("gnoci.toml"),
        out.as_path_untracked().join("gnoci.toml"),
    )
    .unwrap();

    out
}

fn build_and_run(image: &str, root: &Path, should_succeed: bool) -> std::process::Output {
    build(image, root);
    let status = Command::new("skopeo")
        .arg("copy")
        .arg(format!("oci:{image}:test"))
        .arg(format!("docker-daemon:{image}:test"))
        .current_dir(root)
        .status()
        .expect("failed to run skopeo");
    assert!(status.success());
    let output = Command::new("docker")
        .arg("run")
        .arg(format!("{image}:test"))
        .output()
        .expect("failed to run container");
    let stderr = std::str::from_utf8(&output.stderr).unwrap();
    eprintln!("stderr: {stderr}");
    if should_succeed {
        assert!(output.status.success());
    } else {
        assert!(!output.status.success());
    }
    output
}

fn build(image: &str, root: &Path) {
    let status = Command::new(EXE)
        .arg("--tag=test")
        .arg(image)
        .env("RUST_LOG", "trace")
        .current_dir(root)
        .status()
        .expect("failed to run gnoci");
    assert!(status.success());
}

#[test]
fn test_run() {
    let image = curl_test();
    let tmp_dir = setup_test(&image);
    tmp_dir.used_by(|p| {
        // curl test includes linux-vdso, which should be skipped
        // and a cert file that is not an ELF file
        build_and_run(&image, p, true);
    });
}

#[test]
fn test_trivy() {
    let image = curl_test();
    let tmp_dir = setup_test(&image);
    tmp_dir.used_by(|root| {
        build(&image, root);

        // check trivy can scan the image. Get a json spdx and check for packages
        let output = Command::new("trivy")
            .arg("image")
            .arg("--format=json")
            .arg("--list-all-pkgs")
            .arg("--input")
            .arg(format!("./{image}"))
            .current_dir(root)
            .output()
            .expect("failed to run trivy");
        assert!(
            output.status.success(),
            "trivy failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let stdout = std::str::from_utf8(&output.stdout).unwrap();
        // parse with serde_json
        let trivy_output: serde_json::Value =
            serde_json::from_str(stdout).expect("failed to parse json");

        eprintln!("Trivy output: {trivy_output:?}");
        let package_names = trivy_output
            .get("Results")
            .and_then(|results| results.as_array().and_then(|arr| arr.first()))
            .expect("Results should be an array")
            .get("Packages")
            .and_then(|packages| packages.as_array())
            .expect("Packages should be an array")
            .iter()
            .map(|pkg| {
                pkg.get("Name")
                    .and_then(|name| name.as_str())
                    .unwrap_or_default()
            })
            .collect::<Vec<_>>();
        eprintln!("Packages: {package_names:?}");
        // Check for a few specific packages
        assert!(package_names.contains(&"curl") || package_names.contains(&"curl-minimal"));
        assert!(package_names.contains(&"libssl3t64") || package_names.contains(&"openssl-libs"));
        assert!(package_names.contains(&"libgnutls30t64") || package_names.contains(&"krb5-libs"));
    });
}

#[test]
fn test_syft() {
    let image = curl_test();
    let tmp_dir = setup_test(&image);
    tmp_dir.used_by(|root| {
        build(&image, root);

        // check syft can scan the image
        let output = Command::new("syft")
            .arg("scan")
            .arg(format!("oci-dir:{image}"))
            .current_dir(root)
            .output()
            .expect("failed to run syft");
        assert!(
            output.status.success(),
            "syft failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let stdout = std::str::from_utf8(&output.stdout).unwrap();
        eprintln!("syft stdout: {stdout}");
        // Check for a few specific packages (these may vary by distro)
        assert!(stdout.contains("libcurl4t64") || stdout.contains("curl"));
        assert!(stdout.contains("libk5crypto3") || stdout.contains("krb5-libs"));
    });
}

#[test]
fn test_grant() {
    if !is_ubuntu() {
        // Grant doesn't work on the RPM-based images
        eprintln!("Skipping grant test on AlmaLinux");
        return;
    }

    let image = curl_test();
    let tmp_dir = setup_test(&image);
    tmp_dir.used_by(|root| {
        build(&image, root);

        // check grant can detect licenses the image
        let output = Command::new("grant")
            .arg("list")
            .arg(format!("oci-dir:{image}"))
            .current_dir(root)
            .output()
            .expect("failed to run grant");
        assert!(
            output.status.success(),
            "grant failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let stdout = std::str::from_utf8(&output.stdout).unwrap();
        eprintln!("grant stdout: {stdout}");
        // Check for a couple of specific licenses
        assert!(stdout.contains("GPL-3.0-or-later"));
        assert!(stdout.contains("NeoSoft-permissive"));
    });
}

#[test]
fn test_capabilities() {
    let image = if is_ubuntu() {
        "capabilities"
    } else {
        "capabilities-almalinux"
    };
    let tmp_dir = setup_test(image);
    tmp_dir.used_by(|p| {
        let output = build_and_run(image, p, true);
        let stdout = std::str::from_utf8(&output.stdout).unwrap();
        assert!(
            stdout.contains("=ep"),
            "Expected output to contain capability, got: {stdout}"
        );
    });
}
