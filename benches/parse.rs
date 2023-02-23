use std::cell::RefCell;
use std::io::Cursor;
use std::rc::Rc;

use ahash::{HashMap, HashMapExt};
use binrw::BinRead;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pprof::criterion::PProfProfiler;

use ipfixrw::information_elements::get_default_formatter;
use ipfixrw::parser::Message;

fn parse_data_with_template(c: &mut Criterion) {
    // contains templates 500, 999, 501
    let template_bytes = include_bytes!("../resources/tests/parse_temp.bin");

    // contains data sets for templates 999, 500, 999
    let data_bytes = include_bytes!("../resources/tests/parse_data.bin");

    let templates = Rc::new(RefCell::new(HashMap::new()));
    let formatter = Rc::new(get_default_formatter());

    // parse the template so parsing data can be done
    Message::read_args(
        &mut Cursor::new(template_bytes.as_slice()),
        (templates.clone(), formatter.clone()),
    )
    .unwrap();

    c.bench_function("data_with_template", |b| {
        b.iter(|| {
            let _ = Message::read_args(
                &mut Cursor::new(black_box(data_bytes.as_slice())),
                (templates.clone(), formatter.clone()),
            )
            .unwrap();
        })
    });
}

fn parse_template(c: &mut Criterion) {
    // contains templates 500, 999, 501
    let template_bytes = include_bytes!("../resources/tests/parse_temp.bin");

    let templates = Rc::new(RefCell::new(HashMap::new()));
    let formatter = Rc::new(get_default_formatter());

    // parse the template so parsing data can be done
    c.bench_function("template", |b| {
        b.iter(|| {
            let _ = Message::read_args(
                &mut Cursor::new(black_box(template_bytes.as_slice())),
                (templates.clone(), formatter.clone()),
            )
            .unwrap();
        })
    });
}

fn profiler() -> PProfProfiler<'static, 'static> {
    let mut flamegraph_options = pprof::flamegraph::Options::default();
    flamegraph_options.image_width = Some(5000);
    PProfProfiler::new(
        100,
        pprof::criterion::Output::Flamegraph(Some(flamegraph_options)),
    )
}

criterion_group! {
    name = benches;
    config = Criterion::default().with_profiler(profiler());
    targets = parse_template, parse_data_with_template
}
criterion_main!(benches);
