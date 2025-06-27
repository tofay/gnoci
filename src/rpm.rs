use std::{collections::BTreeSet, io::Write, path::PathBuf, process::Command};

use crate::{Entry, LayerBuilder};
use anyhow::{Context, Result};
use tar::{EntryType, Header};

impl<W: Write> LayerBuilder<W> {
    /// Add an RPM manifest to the image.
    /// This copies the format of [AzureLinux](https://github.com/microsoft/azurelinux/blob/64ef81a5b9c855fceaa63006a3f42603386a2c7e/toolkit/docs/how_it_works/5_misc.md?plain=1#L154),
    /// which is already supported by Trivy/Syft/Qualys and more.
    pub(crate) fn write_rpm_manifest<'b>(
        &mut self,
        entries: impl IntoIterator<Item = &'b Entry>,
    ) -> Result<()> {
        // Check if rpm is available
        if Command::new("rpm").arg("--version").output().is_err() {
            return Ok(());
        }

        // determine the owning packages of the files with
        // rpm --query --file --queryformat "%{NAME}\t%{VERSION}-%{RELEASE}\t%{INSTALLTIME}\t%{BUILDTIME}\t%{VENDOR}\t%{EPOCH}\t%{SIZE}\t%{ARCH}\t%{EPOCHNUM}\t%{SOURCERPM}\n" [file]
        // we should filter out "no owning package" lines, keeping only the ones with a valid package name
        let output = Command::new("rpm")
            .arg("--query")
            .arg("--file")
            .arg("--queryformat")
            .arg("%{NAME}\t%{VERSION}-%{RELEASE}\t%{INSTALLTIME}\t%{BUILDTIME}\t%{VENDOR}\t%{EPOCH}\t%{SIZE}\t%{ARCH}\t%{EPOCHNUM}\t%{SOURCERPM}\n")
            .args(entries.into_iter().map(|e| e.source.as_os_str()))
            .output()?;

        // don't check for success as here as rpm returns 1 if no package is found
        let stdout = String::from_utf8_lossy(&output.stdout);
        let lines = stdout
            .lines()
            .filter(|line| !line.contains("not owned by"))
            .collect::<Vec<_>>();

        if !lines.is_empty() {
            let data = lines.join("\n").into_bytes();

            log::debug!("Adding RPM manifest with {} entries", lines.len());

            self.0.insert(
                PathBuf::from("./var/lib/rpmmanifest/container-manifest-2"),
                Box::new(move |writer| {
                    let mut header = Header::new_gnu();
                    header.set_entry_type(EntryType::file());
                    header.set_path("./var/lib/rpmmanifest/container-manifest-2")?;
                    header.set_size(data.len() as u64);
                    header.set_mode(0o644);
                    header.set_uid(0);
                    header.set_gid(0);
                    header.set_cksum();
                    writer.append(&header, &*data)?;
                    Ok(())
                }),
            );
        }

        Ok(())
    }

    /// Detect RPM license files from any files we are adding to the image,
    /// and add them too.
    pub(crate) fn add_rpm_license_files<'a>(
        &mut self,
        entries: impl IntoIterator<Item = &'a Entry>,
    ) -> Result<()> {
        // Check if rpm is available
        if Command::new("rpm").arg("--version").output().is_err() {
            return Ok(());
        }

        let license_files = entries
            .into_iter()
            .map(|entry| {
                // For each entry, run `rpm --query --licensefiles --file <file>`
                // to find the license file, if it exists.
                let output = Command::new("rpm")
                    .arg("--query")
                    .arg("--licensefiles")
                    .arg("--file")
                    .arg(&entry.source)
                    .output()
                    .with_context(|| {
                        format!(
                            "failed to run rpm --query --license --file for {}",
                            entry.source.display()
                        )
                    })?;
                // Do nothing on failure - not all files are RPM packages
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    Ok(stdout
                        .lines()
                        .map(|line| line.to_string())
                        .collect::<Vec<_>>())
                } else {
                    log::trace!(
                        "Failed to run rpm --query --license --file for {}: {}",
                        entry.source.display(),
                        String::from_utf8_lossy(&output.stderr)
                    );
                    Ok(vec![])
                }
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect::<BTreeSet<_>>();

        if !license_files.is_empty() {
            log::debug!("Adding RPM license files: {license_files:?}");
            for file in license_files {
                self.add_file(file);
            }
        }

        Ok(())
    }
}
