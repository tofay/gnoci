//! Extension trait for [`tar::Builder`] to append extended attribute headers.
use std::{
    io::{self, Write},
    path::Path,
};

const PAX_SCHILYXATTR: &str = "SCHILY.xattr.";

/// Extension trait for [`tar::Builder`].
pub trait BuilderExt {
    /// Appends extended attribute headers for the given source path.
    ///
    /// - `src`: The source path whose xattrs will be added as PAX headers.
    ///
    fn append_xattr_header(&mut self, src: &Path) -> io::Result<()>;
}

impl<T: io::Write> BuilderExt for tar::Builder<T> {
    fn append_xattr_header(&mut self, src: &Path) -> io::Result<()> {
        let headers = xattr::list(src)?
            .map(|key| {
                let value = xattr::get(src, &key)?.unwrap_or_default();
                let key = format!("{PAX_SCHILYXATTR}{key}", key = key.to_string_lossy());
                Result::<_, io::Error>::Ok((key, value))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut pax_header = tar::Header::new_gnu();
        let mut pax_data = Vec::new();

        for (key, value) in headers {
            // each entry is "<len> <key>=<value>\n": https://www.ibm.com/docs/en/zos/2.3.0?topic=SSLTBW_2.3.0/com.ibm.zos.v2r3.bpxa500/paxex.html
            let data_len = key.len() + value.len() + 3;
            let mut len_len = 1;
            while data_len + len_len >= 10usize.pow(len_len.try_into().unwrap()) {
                len_len += 1;
            }
            pax_data.write_all((data_len + len_len).to_string().as_bytes())?;
            pax_data.write_all(b" ")?;
            pax_data.write_all(key.as_bytes())?;
            pax_data.write_all(b"=")?;
            pax_data.write_all(&value)?;
            pax_data.write_all(b"\n")?;
        }

        if !pax_data.is_empty() {
            pax_header.set_size(pax_data.len() as u64);
            pax_header.set_entry_type(tar::EntryType::XHeader);
            pax_header.set_cksum();
            self.append(&pax_header, &*pax_data)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::Write;

    use tar::Archive;
    use tempfile::tempdir;

    #[test]
    fn test_xattr() {
        let dir = tempdir().unwrap();
        let src_dir = dir.path().join("src");
        let file_path = src_dir.join("file.txt");
        fs::create_dir(&src_dir).unwrap();
        let mut file = File::create(&file_path).unwrap();
        writeln!(file, "hello world").unwrap();
        drop(file);

        use xattr::set;
        set(&file_path, "user.test", b"val").unwrap();

        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            builder.append_xattr_header(&file_path).unwrap();
            builder
                .append_file(
                    "dst/file.txt",
                    &mut std::fs::File::open(&file_path).unwrap(),
                )
                .unwrap();
        }

        // Read back the archive and check for the file and xattr
        let mut archive = Archive::new(&tar_data[..]);
        let mut found_file = false;
        let mut found_xattr = false;
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap();
            if path.ends_with("dst/file.txt") {
                found_file = true;
            }
            if let Ok(Some(mut pax)) = entry.pax_extensions()
                && pax.any(|p| {
                    p.unwrap()
                        .key()
                        .unwrap()
                        .starts_with("SCHILY.xattr.user.test")
                })
            {
                found_xattr = true;
            }
        }
        assert!(found_file, "file.txt should be in the archive");
        assert!(found_xattr, "xattr should be present in the archive");
    }
}
