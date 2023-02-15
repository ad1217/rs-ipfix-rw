#[cfg(test)]
mod parse_tests {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::io::Cursor;
    use std::net::Ipv4Addr;
    use std::rc::Rc;

    use binrw::BinRead;

    use ipfixrw::properties::get_default_enterprise;
    use ipfixrw::{DataRecord, DataRecordKey, DataRecordValue, Message};

    // shall not cause infinite loop
    #[test]
    fn looper_01() {
        let b = include_bytes!("./looper_01.bin");
        let mut reader = Cursor::new(b.as_slice());

        let templates = Rc::new(RefCell::new(HashMap::new()));
        let formatter = Rc::new(get_default_enterprise());

        let m = Message::read_args(&mut reader, (templates, formatter));
        eprintln!("{m:?}");
    }

    #[test]
    fn test_parse() {
        // contains templates 500, 999, 501
        let template_bytes = include_bytes!("./parse_temp.bin");

        // contains data sets for templates 999, 500, 999
        let data_bytes = include_bytes!("./parse_data.bin");

        let templates = Rc::new(RefCell::new(HashMap::new()));
        let formatter = Rc::new(get_default_enterprise());

        let msg = Message::read_args(
            &mut Cursor::new(template_bytes.as_slice()),
            (templates.clone(), formatter.clone()),
        )
        .unwrap();
        assert!(msg.sets.len() == 1);
        assert!(templates.borrow().len() == 3);
        assert!(templates.borrow().contains_key(&500));
        assert!(templates.borrow().contains_key(&999));
        assert!(templates.borrow().contains_key(&501));
        assert!(Message::read_args(
            &mut Cursor::new(template_bytes.as_slice()),
            (templates.clone(), formatter.clone()),
        )
        .is_ok());

        let data_message = Message::read_args(
            &mut Cursor::new(data_bytes.as_slice()),
            (templates.clone(), formatter.clone()),
        )
        .unwrap();
        let datarecords: Vec<&DataRecord> = data_message.iter_data_records().collect();
        assert!(datarecords.len() == 21);

        // Assert data records are good
        let d0 = datarecords[0];
        assert!(d0.values.len() == 11);
        assert!(
            d0.values
                .get(&DataRecordKey::Str("sourceIPv4Address".to_string()))
                .unwrap()
                == &DataRecordValue::Ipv4Addr(Ipv4Addr::new(172, 19, 219, 50))
        );
        assert!(
            d0.values
                .get(&DataRecordKey::Str("flowEndMilliseconds".to_string()))
                .unwrap()
                == &DataRecordValue::DateTimeMilliseconds(1479840960376)
        );
        assert!(
            d0.values
                .get(&DataRecordKey::Str("destinationTransportPort".to_string()))
                .unwrap()
                == &DataRecordValue::U16(53)
        );
        assert!(
            d0.values
                .get(&DataRecordKey::Str("protocolIdentifier".to_string()))
                .unwrap()
                == &DataRecordValue::U8(17)
        );
    }

    // nprobe -i ens160 -V10 -n localhost:1337 -T "@NTOPNG@"
    #[test]
    fn test_parse_template_enterprise_fields() {
        // 257, 258, 259, 260
        let temp_1 = include_bytes!("./parse_temp_1.bin");
        // 261, 262
        let temp_2 = include_bytes!("./parse_temp_2.bin");

        let templates = Rc::new(RefCell::new(HashMap::new()));
        let formatter = Rc::new(get_default_enterprise());

        let _ = Message::read_args(
            &mut Cursor::new(temp_1.as_slice()),
            (templates.clone(), formatter.clone()),
        )
        .unwrap();
        let _ = Message::read_args(
            &mut Cursor::new(temp_2.as_slice()),
            (templates.clone(), formatter.clone()),
        )
        .unwrap();
        // sum the number of parsed enterprise fields
        let mut enterprise_fields = 0;
        for (_k, v) in templates.borrow().iter() {
            for fs in v {
                enterprise_fields += if fs.enterprise_number.is_some() { 1 } else { 0 };
            }
        }

        assert!(enterprise_fields == 122);
    }

    // // nprobe -i ens160 -V10 -n localhost:1337 -T "@NTOPNG@"
    // #[test]
    // fn test_parse_data_variable_fields() {
    //     // 257, 258, 259, 260
    //     let temp_1 = include_bytes!("./parse_temp_1.bin");
    //     // 261, 262
    //     let temp_2 = include_bytes!("./parse_temp_2.bin");

    //     // dns sample
    //     let d1 = include_bytes!("./dns_samp.bin");

    //     // http sample
    //     let d2 = include_bytes!("./http_samp.bin");

    //     let mut s = state::State::new();
    //     let mut p = parser::Parser::new();

    //     // add custom fields for ntop pen
    //     p.add_custom_field(35632, 205, "DNS_QUERY", formatter::be_string);
    //     p.add_custom_field(35632, 206, "DNS_QUERY_ID", formatter::be_string);
    //     p.add_custom_field(35632, 207, "DNS_QUERY_TYPE", formatter::be_string);
    //     p.add_custom_field(35632, 208, "DNS_RET_CODE", formatter::be_string);
    //     p.add_custom_field(35632, 209, "DNS_NUM_ANSWERS", formatter::be_string);
    //     p.add_custom_field(35632, 352, "DNS_TTL_ANSWER", formatter::be_string);
    //     p.add_custom_field(35632, 398, "DNS_RESPONSE", formatter::be_string);
    //     p.add_custom_field(35632, 180, "HTTP_URL", formatter::be_string);
    //     p.add_custom_field(35632, 360, "HTTP_METHOD", formatter::be_string);
    //     p.add_custom_field(35632, 181, "HTTP_RET_CODE", formatter::be_string);
    //     p.add_custom_field(35632, 182, "HTTP_REFERER", formatter::be_string);
    //     p.add_custom_field(35632, 183, "HTTP_UA", formatter::be_string);
    //     p.add_custom_field(35632, 184, "HTTP_MIME", formatter::be_string);
    //     p.add_custom_field(35632, 187, "HTTP_HOST", formatter::be_string);
    //     p.add_custom_field(35632, 361, "HTTP_SITE", formatter::be_string);
    //     p.add_custom_field(35632, 460, "HTTP_X_FORWARDED_FOR", formatter::be_string);
    //     p.add_custom_field(35632, 461, "HTTP_VIA", formatter::be_string);
    //     p.add_custom_field(35632, 81, "DST_FRAGMENTS", formatter::be_string);
    //     p.add_custom_field(35632, 123, "CLIENT_NW_LATENCY_MS", formatter::be_string);
    //     p.add_custom_field(35632, 124, "SERVER_NW_LATENCY_MS", formatter::be_string);
    //     p.add_custom_field(35632, 79, "SERVER_TCP_FLAGS", formatter::be_string);
    //     p.add_custom_field(35632, 110, "RETRANSMITTED_OUT_PKTS", formatter::be_string);
    //     p.add_custom_field(35632, 111, "OOORDER_IN_PKTS", formatter::be_string);
    //     p.add_custom_field(35632, 188, "TLS_SERVER_NAME", formatter::be_string);
    //     p.add_custom_field(35632, 189, "BITTORRENT_HASH", formatter::be_string);
    //     p.add_custom_field(35632, 416, "TCP_WIN_MAX_IN", formatter::be_string);
    //     p.add_custom_field(35632, 80, "SRC_FRAGMENTS", formatter::be_string);
    //     p.add_custom_field(35632, 78, "CLIENT_TCP_FLAGS", formatter::be_string);
    //     p.add_custom_field(35632, 125, "APPL_LATENCY_MS", formatter::be_string);
    //     p.add_custom_field(35632, 109, "RETRANSMITTED_IN_PKTS", formatter::be_string);
    //     p.add_custom_field(35632, 420, "TCP_WIN_MAX_OUT", formatter::be_string);
    //     p.add_custom_field(35632, 509, "L7_PROTO_RISK", formatter::be_string);
    //     p.add_custom_field(35632, 527, "L7_RISK_SCORE", formatter::be_string);
    //     p.add_custom_field(35632, 278, "GTPV2_APN_NAME", formatter::be_string);
    //     p.add_custom_field(35632, 280, "GTPV2_ULI_MNC", formatter::be_string);
    //     p.add_custom_field(35632, 180, "HTTP_URL", formatter::be_string);
    //     p.add_custom_field(35632, 380, "RTP_RTT", formatter::be_string);
    //     p.add_custom_field(35632, 112, "OOORDER_OUT_PKTS", formatter::be_string);
    //     p.add_custom_field(35632, 118, "L7_PROTO", formatter::be_string);

    //     let _ = p.parse_message(&mut s, temp_1);
    //     let _ = p.parse_message(&mut s, temp_2);

    //     let dns = p.parse_message(&mut s, d1).unwrap();
    //     let records = dns.get_dataset_records();
    //     assert!(records.len() > 0);
    //     let record = records[0];
    //     assert!(record.values.len() == 41);

    //     if let parser::DataRecordValue::String(query) = record
    //         .values
    //         .get(&parser::DataRecordKey::Str("DNS_QUERY"))
    //         .unwrap()
    //     {
    //         assert!(query == "asimov.vortex.data.trafficmanager.net");
    //     }

    //     // http
    //     let http = p.parse_message(&mut s, d2).unwrap();
    //     let records = http.get_dataset_records();
    //     assert!(records.len() > 0);
    //     let record = records[0];
    //     assert!(record.values.len() == 42);

    //     if let parser::DataRecordValue::String(site) = record
    //         .values
    //         .get(&parser::DataRecordKey::Str("HTTP_SITE"))
    //         .unwrap()
    //     {
    //         assert!(site == "example.com");
    //     }
    // }

    // #[test]
    // fn concurrency() {
    //     // A state to be shared between parsing threads
    //     let s = Arc::new(RwLock::new(state::State::new()));

    //     // First thread to parse a template test
    //     let s1 = s.clone();
    //     let j1 = std::thread::spawn(move || {
    //         // contains templates 500, 999, 501
    //         let template_bytes = include_bytes!("./parse_temp.bin");
    //         let p = parser::Parser::new();
    //         let _m = p.parse_message_async(s1, template_bytes);
    //     });

    //     // Second thread to parse data set
    //     let s2 = s.clone();
    //     let j2 = std::thread::spawn(move || {
    //         // contains data sets for templates 999, 500, 999
    //         let data_bytes = include_bytes!("./parse_data.bin");
    //         let p = parser::Parser::new();
    //         let _m = p.parse_message_async(s2, data_bytes);
    //     });

    //     let _r1 = j1.join();
    //     let _r2 = j2.join();

    //     // Assert state mutated from threads
    //     assert!(s.read().unwrap().len() == 3);
    //     assert!(s.read().unwrap().templates_len() == 3);
    // }
}
