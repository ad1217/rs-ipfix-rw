#[cfg(test)]
mod round_trip_tests {
    use std::cell::RefCell;
    use std::io::{Cursor, Seek};
    use std::rc::Rc;

    use ahash::{HashMap, HashMapExt};
    use binrw::{BinRead, BinWrite};

    use ipfixrw::properties::get_default_formatter;
    use ipfixrw::Message;

    #[test]
    fn test_parse_rw() -> binrw::BinResult<()> {
        // contains templates 500, 999, 501
        let template_bytes = include_bytes!("./parse_temp.bin");

        // contains data sets for templates 999, 500, 999
        let data_bytes = include_bytes!("./parse_data.bin");

        let templates = Rc::new(RefCell::new(HashMap::new()));
        let formatter = Rc::new(get_default_formatter());

        let msg = Message::read_args(
            &mut Cursor::new(template_bytes.as_slice()),
            (templates.clone(), formatter.clone()),
        )?;
        let mut template_writer = Cursor::new(Vec::new());
        msg.write_args(&mut template_writer, (templates.clone(), formatter.clone()))?;
        assert_eq!(template_bytes, template_writer.into_inner().as_slice());

        let data_message = Message::read_args(
            &mut Cursor::new(data_bytes.as_slice()),
            (templates.clone(), formatter.clone()),
        )?;

        let mut data_writer = Cursor::new(Vec::new());
        data_message.write_args(&mut data_writer, (templates.clone(), formatter.clone()))?;
        data_writer.seek(std::io::SeekFrom::Start(0))?;

        let data_message2 = Message::read_args(
            &mut Cursor::new(data_bytes.as_slice()),
            (templates.clone(), formatter.clone()),
        )?;

        let mut temp_writer = Cursor::new(Vec::new());
        data_message
            .sets
            .write_args(&mut temp_writer, (templates.clone(), formatter.clone()))?;

        assert_eq!(data_message, data_message2);
        assert_eq!(data_bytes, data_writer.into_inner().as_slice());

        Ok(())
    }
}
