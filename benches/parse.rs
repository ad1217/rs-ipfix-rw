use std::cell::RefCell;
use std::collections::HashMap;
use std::io::Cursor;
use std::rc::Rc;

use bencher::{benchmark_group, benchmark_main, black_box, Bencher};
use binrw::BinRead;

use ipfixrw::properties::get_default_enterprise;
use ipfixrw::Message;

fn parse_data_with_template(bench: &mut Bencher) {
    // contains templates 500, 999, 501
    let template_bytes = include_bytes!("../tests/parse_temp.bin");

    // contains data sets for templates 999, 500, 999
    let data_bytes = include_bytes!("../tests/parse_data.bin");

    let templates = Rc::new(RefCell::new(HashMap::new()));
    let formatter = Rc::new(get_default_enterprise());

    // parse the template so parsing data can be done
    Message::read_args(
        &mut Cursor::new(template_bytes.as_slice()),
        (templates.clone(), formatter.clone()),
    )
    .unwrap();

    bench.iter(|| {
        let _ = Message::read_args(
            &mut Cursor::new(black_box(data_bytes.as_slice())),
            (templates.clone(), formatter.clone()),
        )
        .unwrap();
    })
}

fn parse_template(bench: &mut Bencher) {
    // contains templates 500, 999, 501
    let template_bytes = include_bytes!("../tests/parse_temp.bin");

    let templates = Rc::new(RefCell::new(HashMap::new()));
    let formatter = Rc::new(get_default_enterprise());

    // parse the template so parsing data can be done
    bench.iter(|| {
        let _ = Message::read_args(
            &mut Cursor::new(black_box(template_bytes.as_slice())),
            (templates.clone(), formatter.clone()),
        )
        .unwrap();
    })
}

benchmark_group!(benches, parse_template, parse_data_with_template);
benchmark_main!(benches);
