use std::{
    collections::HashSet,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

use crate::{Entry, LayerBuilder};
use anyhow::{Context, Result, bail};
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

        let mut found_debian_package = false;

        for package in entries
            .into_iter()
            .map(|entry| {
                let output = Command::new("dpkg")
                    .arg("-S")
                    .arg(&entry.source)
                    .output()
                    .context(format!(
                        "failed to run dpkg -S for {}",
                        entry.source.display()
                    ))?;

                if output.status.success() {
                    let package_info = String::from_utf8_lossy(&output.stdout);
                    let first_line = package_info.lines().next().unwrap();
                    if first_line.starts_with("diversion by ") {
                        Ok(None)
                    } else {
                        // Handle "<package>:(<arch>:) <file>" format
                        let package_arch = first_line
                            .split(' ')
                            .next()
                            .expect("package name not found")
                            .strip_suffix(":")
                            .expect("unexpected dpkg -S output");
                        Ok(Some(
                            package_arch
                                .split_once(':')
                                .map(|(package, _arch)| package.to_string())
                                .unwrap_or(package_arch.to_string()),
                        ))
                    }
                } else {
                    log::trace!("Failed to run dpkg -S for {}", entry.source.display());
                    Ok(None)
                }
            })
            .collect::<Result<HashSet<_>>>()?
            .into_iter()
            .flatten()
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
