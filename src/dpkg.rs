use std::{
    collections::HashSet,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

use crate::{Entry, LayerBuilder};
use anyhow::{Context, Result, anyhow, bail};
use tar::{EntryType, Header};

impl<W: Write> LayerBuilder<W> {
    /// Write dpkg status files for the given files,
    /// in `/var/lib/dpkg/status.d/` format as used by Google Distroless containers.
    pub(crate) fn add_dpkg_files<'a>(
        &mut self,
        entries: impl IntoIterator<Item = &'a Entry>,
    ) -> Result<()> {
        // Check if dpkg is available
        if Command::new("dpkg").arg("--version").output().is_err() {
            return Ok(());
        }

        // Run a single `dpkg -S [file]` command for all entries,
        // and parse the output to determine which packages own the files.
        let output = Command::new("dpkg")
            .arg("-S")
            .args(entries.into_iter().map(|e| &e.source))
            .output()
            .context("failed to run dpkg -S [file]")?;

        // We don't check the exit status here, because dpkg -S can return non-zero
        // if no package owns the file, which is expected.

        let mut found_debian_package = false;
        let package_info = String::from_utf8_lossy(&output.stdout);
        for package in package_info
            .lines()
            .map(parse_dpkg_s_line)
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect::<HashSet<_>>()
        {
            found_debian_package = true;
            // use `dpkg -s <package>` to get package status, and write to `/var/lib/dpkg.status.d/<package>`
            let output = Command::new("dpkg")
                .arg("-s")
                .arg(&package)
                .output()
                .context(format!("failed to run dpkg -s for package {package}"))?;
            if !output.status.success() {
                bail!("dpkg -s failed for {}", package);
            }

            // if copyright file exists for this package, add it too
            let copyright_path = PathBuf::from(format!("/usr/share/doc/{package}/copyright"));
            if copyright_path.exists() {
                self.add_file(copyright_path);
            }

            self.0.insert(
                PathBuf::from(format!("./var/lib/dpkg/status.d/{package}")),
                Box::new(move |writer| {
                    let mut header = Header::new_gnu();
                    header.set_entry_type(EntryType::file());
                    header.set_path(format!("./var/lib/dpkg/status.d/{package}"))?;
                    header.set_size(output.stdout.len() as u64);
                    header.set_mode(0o644);
                    header.set_uid(0);
                    header.set_gid(0);
                    header.set_cksum();
                    writer.append(&header, &*output.stdout)?;
                    Ok(())
                }),
            );
        }

        if found_debian_package {
            if Path::new("/etc/lsb-release").exists() {
                self.add_file("/etc/lsb-release");
            }

            if Path::new("/etc/debian_version").exists() {
                self.add_file("/etc/debian_version");
            }
        }

        Ok(())
    }
}

fn parse_dpkg_s_line(line: &str) -> Result<Vec<String>> {
    log::trace!("dpkg -S output line: {line}");
    if line.starts_with("diversion by ") {
        Ok(vec![])
    } else if line.contains(',') {
        // Handle "<package>, <other package>: <file>"
        Ok(line
            .split(',')
            .map(|part| {
                let package = part.split(':').next().unwrap();
                package.trim().to_string()
            })
            .collect::<Vec<_>>())
    } else {
        // Handle "<package>:(<arch>:) <file>" format
        let package_arch = line
            .split(' ')
            .next()
            .ok_or_else(|| anyhow!("dpkg -S output does not contain package name"))?
            .strip_suffix(":")
            .ok_or_else(|| {
                anyhow!(format!(
                    "dpkg -S output does not contain package architecture: {}",
                    line
                ))
            })?;
        Ok(vec![
            package_arch
                .split_once(':')
                .map(|(package, _arch)| package.to_string())
                .unwrap_or(package_arch.to_string()),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dpkg_s_line_diversion() {
        let line = "diversion by dpkg-divert from: /usr/bin/pager to: /usr/bin/pager.distrib";
        let result = parse_dpkg_s_line(line).unwrap();
        assert_eq!(result, Vec::<String>::new());
    }

    #[test]
    fn test_parse_dpkg_s_line_multiple_packages() {
        let line = "libc6:amd64, libc6-dev:amd64: /usr/include/stdio.h";
        let result = parse_dpkg_s_line(line).unwrap();
        assert_eq!(result, vec!["libc6".to_string(), "libc6-dev".to_string()]);
    }

    #[test]
    fn test_parse_dpkg_s_line_single_package_with_arch() {
        let line = "bash:amd64: /bin/bash";
        let result = parse_dpkg_s_line(line).unwrap();
        assert_eq!(result, vec!["bash".to_string()]);
    }

    #[test]
    fn test_parse_dpkg_s_line_single_package_without_arch() {
        let line = "coreutils: /usr/bin/ls";
        let result = parse_dpkg_s_line(line).unwrap();
        assert_eq!(result, vec!["coreutils".to_string()]);
    }

    #[test]
    fn test_parse_dpkg_s_line_three_packages() {
        let line = "pkg1:amd64, pkg2:i386, pkg3: /some/file";
        let result = parse_dpkg_s_line(line).unwrap();
        assert_eq!(
            result,
            vec!["pkg1".to_string(), "pkg2".to_string(), "pkg3".to_string()]
        );
    }

    #[test]
    fn test_parse_dpkg_s_line_packages_with_spaces() {
        let line = "package-name:amd64 , another-pkg : /some/path";
        let result = parse_dpkg_s_line(line).unwrap();
        assert_eq!(
            result,
            vec!["package-name".to_string(), "another-pkg".to_string()]
        );
    }

    #[test]
    fn test_parse_dpkg_s_line_empty_line() {
        let line = "";
        let result = parse_dpkg_s_line(line);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_dpkg_s_line_no_colon() {
        let line = "invalid-format /some/file";
        let result = parse_dpkg_s_line(line);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_dpkg_s_line_no_space_after_package() {
        let line = "package:amd64:/some/file";
        let result = parse_dpkg_s_line(line);
        assert!(result.is_err());
    }
}
