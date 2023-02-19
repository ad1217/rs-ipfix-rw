#[cfg(test)]
mod round_trip_tests {
    use std::cell::RefCell;
    use std::io::Cursor;
    use std::rc::Rc;

    use ahash::{HashMap, HashMapExt};
    use binrw::{BinRead, BinWrite};
    use test_case::test_case;

    use ipfixrw::properties::get_default_formatter;
    use ipfixrw::Message;

    #[test_case(&["parse_temp.bin", "parse_data.bin"], 0; "parse sample")]
    #[test_case(&["parse_temp_1.bin", "dns_samp.bin"], 4; "nprobe dns sample")]
    #[test_case(&["parse_temp_2.bin","http_samp.bin"], 4; "nprobe http sample")]
    fn test_round_trip(filenames: &[&'static str], alignment: u16) -> binrw::BinResult<()> {
        let templates = Rc::new(RefCell::new(HashMap::new()));
        let formatter = Rc::new(get_default_formatter());

        for filename in filenames {
            let path: std::path::PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests", filename]
                .iter()
                .collect();
            let file_bytes = std::fs::read(path)?;

            let msg = Message::read_args(
                &mut Cursor::new(file_bytes.as_slice()),
                (templates.clone(), formatter.clone()),
            )?;
            let mut writer = Cursor::new(Vec::new());
            msg.write_args(
                &mut writer,
                (templates.clone(), formatter.clone(), alignment),
            )?;
            similar_asserts::assert_eq!(expected: file_bytes, actual: writer.into_inner().as_slice());
        }

        Ok(())
    }
}
