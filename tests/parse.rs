use std::cell::RefCell;
use std::net::Ipv4Addr;
use std::rc::Rc;
use std::sync::{Arc, RwLock};

use ahash::{HashMap, HashMapExt};
use binrw::BinRead;

use ipfixrw::information_elements::get_default_formatter;
use ipfixrw::parse_ipfix_message;
use ipfixrw::parser::{DataRecord, DataRecordKey, DataRecordType, DataRecordValue};
use ipfixrw::template_store::Template;

// shall not cause infinite loop
#[test]
fn looper_01() {
    let b = include_bytes!("../resources/tests/looper_01.bin");

    let templates = Rc::new(RefCell::new(HashMap::new()));
    let formatter = Rc::new(get_default_formatter());

    let m = parse_ipfix_message(b, templates, formatter);
    assert!(m.is_err());
}

#[test]
fn test_parse() {
    // contains templates 500, 999, 501
    let template_bytes = include_bytes!("../resources/tests/parse_temp.bin");

    // contains data sets for templates 999, 500, 999
    let data_bytes = include_bytes!("../resources/tests/parse_data.bin");

    let templates = Rc::new(RefCell::new(HashMap::new()));
    let formatter = Rc::new(get_default_formatter());

    let msg = parse_ipfix_message(template_bytes, templates.clone(), formatter.clone()).unwrap();
    assert_eq!(msg.sets.len(), 1);
    assert_eq!(templates.borrow().len(), 3);
    assert!(templates.borrow().contains_key(&500));
    assert!(templates.borrow().contains_key(&999));
    assert!(templates.borrow().contains_key(&501));
    assert!(parse_ipfix_message(template_bytes, templates.clone(), formatter.clone(),).is_ok());

    let data_message = parse_ipfix_message(data_bytes, templates, formatter.clone()).unwrap();
    let datarecords: Vec<&DataRecord> = data_message.iter_data_records().collect();
    assert_eq!(datarecords.len(), 21);

    // Assert data records are good
    let d0 = datarecords[0];
    assert_eq!(d0.values.len(), 11);
    assert_eq!(
        d0.values
            .get(&DataRecordKey::Str("sourceIPv4Address"))
            .unwrap(),
        &DataRecordValue::Ipv4Addr(Ipv4Addr::new(172, 19, 219, 50))
    );
    assert_eq!(
        d0.values
            .get(&DataRecordKey::Str("flowEndMilliseconds"))
            .unwrap(),
        &DataRecordValue::DateTimeMilliseconds(1479840960376)
    );
    assert_eq!(
        d0.values
            .get(&DataRecordKey::Str("destinationTransportPort"))
            .unwrap(),
        &DataRecordValue::U16(53)
    );
    assert_eq!(
        d0.values
            .get(&DataRecordKey::Str("protocolIdentifier"))
            .unwrap(),
        &DataRecordValue::U8(17)
    );
}

// nprobe -i ens160 -V10 -n localhost:1337 -T "@NTOPNG@"
#[test]
fn test_parse_template_enterprise_fields() {
    // 257, 258, 259, 260
    let temp_1 = include_bytes!("../resources/tests/parse_temp_1.bin");
    // 261, 262
    let temp_2 = include_bytes!("../resources/tests/parse_temp_2.bin");

    let templates = Rc::new(RefCell::new(HashMap::new()));
    let formatter = Rc::new(get_default_formatter());

    let _ = parse_ipfix_message(temp_1, templates.clone(), formatter.clone()).unwrap();
    let _ = parse_ipfix_message(temp_2, templates.clone(), formatter.clone()).unwrap();
    // sum the number of parsed enterprise fields
    let enterprise_fields = templates
        .borrow()
        .values()
        .flat_map(|t| match t {
            Template::Template(field_specifiers) => field_specifiers,
            Template::OptionsTemplate(field_specifiers) => field_specifiers,
        })
        .filter(|fs| fs.enterprise_number.is_some())
        .count();

    assert_eq!(enterprise_fields, 122);
}

// nprobe -i ens160 -V10 -n localhost:1337 -T "@NTOPNG@"
#[test]
fn test_parse_data_variable_fields() {
    // 257, 258, 259, 260
    let temp_1 = include_bytes!("../resources/tests/parse_temp_1.bin");
    // 261, 262
    let temp_2 = include_bytes!("../resources/tests/parse_temp_2.bin");

    // dns sample
    let d1 = include_bytes!("../resources/tests/dns_samp.bin");

    // http sample
    let d2 = include_bytes!("../resources/tests/http_samp.bin");

    let templates = Rc::new(RefCell::new(HashMap::new()));
    let mut formatter = get_default_formatter();

    // add custom fields for ntop pen
    ipfixrw::extend_formatter!(formatter += {
        (35632, 78) => ("CLIENT_TCP_FLAGS", UnsignedInt),
        (35632, 79) => ("SERVER_TCP_FLAGS", UnsignedInt),
        (35632, 80) => ("SRC_FRAGMENTS", UnsignedInt),
        (35632, 81) => ("DST_FRAGMENTS", UnsignedInt),
        (35632, 109) => ("RETRANSMITTED_IN_PKTS", UnsignedInt),
        (35632, 110) => ("RETRANSMITTED_OUT_PKTS", UnsignedInt),
        (35632, 111) => ("OOORDER_IN_PKTS", UnsignedInt),
        (35632, 112) => ("OOORDER_OUT_PKTS", UnsignedInt),
        (35632, 118) => ("L7_PROTO", UnsignedInt),
        (35632, 123) => ("CLIENT_NW_LATENCY_MS", UnsignedInt),
        (35632, 124) => ("SERVER_NW_LATENCY_MS", UnsignedInt),
        (35632, 125) => ("APPL_LATENCY_MS", UnsignedInt),
        (35632, 180) => ("HTTP_URL", String),
        (35632, 181) => ("HTTP_RET_CODE", UnsignedInt),
        (35632, 182) => ("HTTP_REFERER", String),
        (35632, 183) => ("HTTP_UA", String),
        (35632, 184) => ("HTTP_MIME", String),
        (35632, 187) => ("HTTP_HOST", String),
        (35632, 188) => ("TLS_SERVER_NAME", String),
        (35632, 189) => ("BITTORRENT_HASH", String),
        (35632, 205) => ("DNS_QUERY", String),
        (35632, 206) => ("DNS_QUERY_ID", UnsignedInt),
        (35632, 207) => ("DNS_QUERY_TYPE", UnsignedInt),
        (35632, 208) => ("DNS_RET_CODE", UnsignedInt),
        (35632, 209) => ("DNS_NUM_ANSWERS", UnsignedInt),
        (35632, 278) => ("GTPV2_APN_NAME", String),
        (35632, 280) => ("GTPV2_ULI_MNC", UnsignedInt),
        (35632, 352) => ("DNS_TTL_ANSWER", UnsignedInt),
        (35632, 360) => ("HTTP_METHOD", String),
        (35632, 361) => ("HTTP_SITE", String),
        (35632, 380) => ("RTP_RTT", UnsignedInt),
        (35632, 398) => ("DNS_RESPONSE", String),
        (35632, 416) => ("TCP_WIN_MAX_IN", UnsignedInt),
        (35632, 420) => ("TCP_WIN_MAX_OUT", UnsignedInt),
        (35632, 460) => ("HTTP_X_FORWARDED_FOR", String),
        (35632, 461) => ("HTTP_VIA", String),
        (35632, 509) => ("L7_PROTO_RISK", UnsignedInt),
        (35632, 527) => ("L7_RISK_SCORE", UnsignedInt)
    });
    let formatter = Rc::new(formatter);

    assert!(parse_ipfix_message(temp_1, templates.clone(), formatter.clone()).is_ok());
    assert!(parse_ipfix_message(temp_2, templates.clone(), formatter.clone()).is_ok());

    let dns = parse_ipfix_message(d1, templates.clone(), formatter.clone()).unwrap();
    println!("{dns:#?}");
    let records: Vec<&DataRecord> = dns.iter_data_records().collect();
    assert!(!records.is_empty());
    let record = records[0];
    assert_eq!(record.values.len(), 41);

    if let DataRecordValue::String(query) =
        record.values.get(&DataRecordKey::Str("DNS_QUERY")).unwrap()
    {
        assert_eq!(query, "asimov.vortex.data.trafficmanager.net");
    }

    // http
    let http = parse_ipfix_message(d2, templates, formatter.clone()).unwrap();
    let records: Vec<&DataRecord> = http.iter_data_records().collect();
    assert!(!records.is_empty());
    let record = records[0];
    assert_eq!(record.values.len(), 42);

    if let DataRecordValue::String(site) =
        record.values.get(&DataRecordKey::Str("HTTP_SITE")).unwrap()
    {
        assert_eq!(site, "example.com");
    }
}

#[test]
fn concurrency() {
    // A state to be shared between parsing threads
    let templates = Arc::new(RwLock::new(HashMap::new()));

    // First thread to parse a template test
    let t1 = templates.clone();
    let j1 = std::thread::spawn(move || {
        // contains templates 500, 999, 501
        let template_bytes = include_bytes!("../resources/tests/parse_temp.bin");
        let formatter = Rc::new(get_default_formatter());
        let _m = parse_ipfix_message(template_bytes, Rc::new(t1), formatter.clone());
    });

    // Second thread to parse data set
    let t2 = templates.clone();
    let j2 = std::thread::spawn(move || {
        // contains data sets for templates 999, 500, 999
        let data_bytes = include_bytes!("../resources/tests/parse_data.bin");
        let formatter = Rc::new(get_default_formatter());
        let _m = parse_ipfix_message(data_bytes, Rc::new(t2), formatter.clone());
    });

    let _r1 = j1.join();
    let _r2 = j2.join();

    // Assert state mutated from threads
    assert!(templates.read().unwrap().len() == 3);
}
