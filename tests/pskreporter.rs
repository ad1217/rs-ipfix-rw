//! Samples from pskreporter documentation <https://pskreporter.info/pskdev.html>

#[cfg(test)]
mod pskreporter_tests {
    use std::{cell::RefCell, io::Cursor, rc::Rc};

    use ahash::{HashMap, HashMapExt};
    use binrw::{BinRead, BinResult, BinWrite};
    use test_case::test_case;

    use ipfixrw::{
        data_record,
        properties::{get_default_formatter, Formatter},
        DataRecord, DataRecordKey, DataRecordType, DataRecordValue, FieldSpecifier, Message,
        OptionsTemplateRecord, Records, Set, TemplateRecord,
    };

    // receiver information templates
    #[test_case(
        concat!(
            "00030024999200030000",
            "8002FFFF0000768F",
            "8004FFFF0000768F",
            "8008FFFF0000768F",
            "0000",
        ),
        Set {
            records: Records::OptionsTemplate(vec![OptionsTemplateRecord {
                template_id: 0x9992,
                scope_field_count: 0,
                field_specifiers: vec![
                    FieldSpecifier::new(Some(30351), 2, u16::MAX),
                    FieldSpecifier::new(Some(30351), 4, u16::MAX),
                    FieldSpecifier::new(Some(30351), 8, u16::MAX),
                ],
            }]),
        } ; "receiverCallsign, receiverLocator, decodingSoftware")]
    #[test_case(
        concat!(
            "0003002C999200040000",
            "8002FFFF0000768F",
            "8004FFFF0000768F",
            "8008FFFF0000768F",
            "8009FFFF0000768F",
            "0000",
        ),
        Set {
            records: Records::OptionsTemplate(vec![OptionsTemplateRecord {
                template_id: 0x9992,
                scope_field_count: 0,
                field_specifiers: vec![
                    FieldSpecifier::new(Some(30351), 2, u16::MAX),
                    FieldSpecifier::new(Some(30351), 4, u16::MAX),
                    FieldSpecifier::new(Some(30351), 8, u16::MAX),
                    FieldSpecifier::new(Some(30351), 9, u16::MAX),
                ],
            }]),
        } ; "receiverCallsign, receiverLocator, decodingSoftware, anntennaInformation")]
    // sender information templates
    #[test_case(
        concat!(
            "0002002C99930005",
            "8001FFFF0000768F",
            "800500040000768F",
            "800AFFFF0000768F",
            "800B00010000768F",
            "00960004",
        ), Set {
            records: Records::Template(vec![TemplateRecord {
                template_id: 0x9993,
                field_specifiers: vec![
                    FieldSpecifier::new(Some(30351), 1, u16::MAX),
                    FieldSpecifier::new(Some(30351), 5, 4),
                    FieldSpecifier::new(Some(30351), 10, u16::MAX),
                    FieldSpecifier::new(Some(30351), 11, 1),
                    FieldSpecifier::new(None, 150, 4),
                ],
            }])
        } ; "senderCallsign, frequency, mode, informationSource (1 byte), flowStartSeconds")]
    #[test_case(
        concat!(
            "0002003499930006",
            "8001FFFF0000768F",
            "800500040000768F",
            "800AFFFF0000768F",
            "800B00010000768F",
            "8003FFFF0000768F",
            "00960004",
        ), Set {
            records: Records::Template(vec![TemplateRecord {
                template_id: 0x9993,
                field_specifiers: vec![
                    FieldSpecifier::new(Some(30351), 1, u16::MAX),
                    FieldSpecifier::new(Some(30351), 5, 4),
                    FieldSpecifier::new(Some(30351), 10, u16::MAX),
                    FieldSpecifier::new(Some(30351), 11, 1),
                    FieldSpecifier::new(Some(30351), 3, u16::MAX),
                    FieldSpecifier::new(None, 150, 4),
                ],
            }])
        } ; "senderCallsign, frequency, mode, informationSource (1 byte), senderLocator, flowStartSeconds")]
    #[test_case(
        concat!(
            "0002003C99930007",
            "8001FFFF0000768F",
            "800500040000768F",
            "800600010000768F",
            "800700010000768F",
            "800AFFFF0000768F",
            "800B00010000768F",
            "00960004",
        ), Set {
            records: Records::Template(vec![TemplateRecord {
                template_id: 0x9993,
                field_specifiers: vec![
                    FieldSpecifier::new(Some(30351), 1, u16::MAX),
                    FieldSpecifier::new(Some(30351), 5, 4),
                    FieldSpecifier::new(Some(30351), 6, 1),
                    FieldSpecifier::new(Some(30351), 7, 1),
                    FieldSpecifier::new(Some(30351), 10, u16::MAX),
                    FieldSpecifier::new(Some(30351), 11, 1),
                    FieldSpecifier::new(None, 150, 4),
                ],
            }])
        } ; "senderCallsign, frequency, sNR (1 byte), iMD (1 byte), mode, informationSource (1 byte), flowStartSeconds")]
    #[test_case(
        concat!(
            "0002004499930008",
            "8001FFFF0000768F",
            "800500040000768F",
            "800600010000768F",
            "800700010000768F",
            "800AFFFF0000768F",
            "800B00010000768F",
            "8003FFFF0000768F",
            "00960004",
        ), Set {
            records: Records::Template(vec![TemplateRecord {
                template_id: 0x9993,
                field_specifiers: vec![
                    FieldSpecifier::new(Some(30351), 1, u16::MAX),
                    FieldSpecifier::new(Some(30351), 5, 4),
                    FieldSpecifier::new(Some(30351), 6, 1),
                    FieldSpecifier::new(Some(30351), 7, 1),
                    FieldSpecifier::new(Some(30351), 10, u16::MAX),
                    FieldSpecifier::new(Some(30351), 11, 1),
                    FieldSpecifier::new(Some(30351), 3, u16::MAX),
                    FieldSpecifier::new(None, 150, 4),
                ],
            }])
        } ; "senderCallsign, frequency, sNR (1 byte), iMD (1 byte), mode, informationSource (1 byte), senderLocator, flowStartSeconds")]

    fn test_template_example(bytes_str: &'static str, expected_set: Set) -> BinResult<()> {
        let template_bytes = hex::decode(bytes_str).unwrap();

        let parsed = Set::read(&mut Cursor::new(template_bytes.clone()))?;
        similar_asserts::assert_eq!(expected: expected_set, parsed: parsed);

        let mut writer = Cursor::new(Vec::new());
        expected_set.write_args(&mut writer, (Rc::default(), Rc::default(), 4))?;
        similar_asserts::assert_eq!(expected: template_bytes, parsed: writer.into_inner());

        Ok(())
    }

    fn pskreporter_formatter() -> Formatter {
        let mut formatter = get_default_formatter();

        ipfixrw::extend_formatter!(formatter += {
            (30351, 1) => ("senderCallsign", String),
            (30351, 2) => ("receiverCallsign", String),
            (30351, 3) => ("senderLocator", String),
            (30351, 4) => ("receiverLocator", String),
            (30351, 5) => ("frequency", UnsignedInt),
            (30351, 6) => ("sNR", UnsignedInt),
            (30351, 7) => ("iMD", UnsignedInt),
            (30351, 8) => ("decoderSoftware", String),
            (30351, 9) => ("antennaInformation", String),
            (30351, 10) => ("mode", String),

            (30351, 11) => ("informationSource", UnsignedInt),

            (30351, 12) => ("persistentIdentifier", String)
        });
        formatter
    }

    #[test]
    fn test_full_examples() -> BinResult<()> {
        #[rustfmt::skip]
        let full_packet_bytes = hex::decode(
            concat!(
                "000A00AC479532720000000100000000",
                "00030024", "999200030000", "8002FFFF0000768F", "8004FFFF0000768F", "8008FFFF0000768F", "0000",
                // TODO: I believe there is a typo in the source document for this: the second
                // segment is listed as "99930003" which would indicate only 3 fields, but there are
                // clearly 5
                "0002002C", "99930005", "8001FFFF0000768F", "800500040000768F", "800AFFFF0000768F", "800B00010000768F", "00960004",
                "99920020", "044E314451", "06464E3432686E", "0D486F6D65627265772076352E36", "0000",
                // TODO: another typo, fourth segment was "0350534C" ("PSL") should be "PSK"
                "9993002C", "044E314451", "00D6B327", "0350534B", "01", "47953254",
                // TODO: same typo as before, but in third segment
                "064B42314D4258", "00D6B4CB", "0350534B", "01", "47953268",
                "0000",
            )).unwrap();

        let expected_full_message = Message {
            export_time: 1200960114,
            sequence_number: 1,
            observation_domain_id: 0,
            sets: vec![
                Set {
                    records: Records::OptionsTemplate(vec![OptionsTemplateRecord {
                        template_id: 0x9992,
                        scope_field_count: 0,
                        field_specifiers: vec![
                            FieldSpecifier::new(Some(30351), 2, u16::MAX),
                            FieldSpecifier::new(Some(30351), 4, u16::MAX),
                            FieldSpecifier::new(Some(30351), 8, u16::MAX),
                        ],
                    }]),
                },
                Set {
                    records: Records::Template(vec![TemplateRecord {
                        template_id: 0x9993,
                        field_specifiers: vec![
                            FieldSpecifier::new(Some(30351), 1, u16::MAX),
                            FieldSpecifier::new(Some(30351), 5, 4),
                            FieldSpecifier::new(Some(30351), 10, u16::MAX),
                            FieldSpecifier::new(Some(30351), 11, 1),
                            FieldSpecifier::new(None, 150, 4),
                        ],
                    }]),
                },
                Set {
                    records: Records::Data {
                        set_id: 0x9992,
                        data: vec![data_record! {
                            "receiverCallsign": String("N1DQ".into()),
                            "receiverLocator": String("FN42hn".into()),
                            "decoderSoftware": String("Homebrew v5.6".into()),
                        }],
                    },
                },
                Set {
                    records: Records::Data {
                        set_id: 0x9993,
                        data: vec![
                            data_record! {
                                "senderCallsign": String("N1DQ".into()),
                                "frequency": U32(14070567),
                                "mode": String("PSK".into()),
                                "informationSource": U8(1),
                                "flowStartSeconds": DateTimeSeconds(1200960084),
                            },
                            data_record! {
                                "senderCallsign": String("KB1MBX".into()),
                                "frequency": U32(14070987),
                                "mode": String("PSK".into()),
                                "informationSource": U8(1),
                                "flowStartSeconds": DateTimeSeconds(1200960104),
                            },
                        ],
                    },
                },
            ],
        };

        #[rustfmt::skip]
        // TODO: same typos in source as full packet
        let data_only_packet_bytes =hex::decode(
            concat!(
                "000A005C479532720000000400000000",
                "99920020", "044E314451", "06464E3432686E", "0D486F6D65627265772076352E36", "0000",
                "9993002C", "044E314451", "00D6B327", "0350534B", "01", "47953254",
                "064B42314D4258", "00D6B4CB", "0350534B", "01", "47953268",
                "0000",
            )).unwrap();

        let expected_data_only_message = Message {
            export_time: 1200960114,
            sequence_number: 4,
            observation_domain_id: 0,
            // same as full packet, but without the templates and option templates sets
            sets: expected_full_message.sets[2..].to_vec(),
        };

        let templates = Rc::new(RefCell::new(HashMap::new()));
        let formatter = Rc::new(pskreporter_formatter());

        let full_message = Message::read_args(
            &mut Cursor::new(full_packet_bytes.as_slice()),
            (templates.clone(), formatter.clone()),
        )?;

        similar_asserts::assert_eq!(expected: expected_full_message, actual: full_message);

        let data_only_message = Message::read_args(
            &mut Cursor::new(data_only_packet_bytes.as_slice()),
            (templates.clone(), formatter.clone()),
        )?;

        similar_asserts::assert_eq!(
            expected: expected_data_only_message,
            actual: data_only_message
        );

        Ok(())
    }
}
