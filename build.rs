//! Build the information elements hashmap from the official iana IPFIX Entities csv
//! <https://www.iana.org/assignments/ipfix/ipfix.xhtml>

use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=resources/ipfix-information-elements.csv");
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("ipfix-information-elements.rs");
    let mut out_file = File::create(dest_path).unwrap();

    let in_file = File::open("resources/ipfix-information-elements.csv").unwrap();
    let mut csv_reader = csv::Reader::from_reader(in_file);

    let headers = csv_reader.headers().unwrap();
    let element_id_pos = headers.iter().position(|x| x == "ElementID").unwrap();
    let name_pos = headers.iter().position(|x| x == "Name").unwrap();
    let abstract_data_type_pos = headers
        .iter()
        .position(|x| x == "Abstract Data Type")
        .unwrap();

    write!(
        out_file,
        "/// default information element types for no enterprise / enterprise number 0\n\
         pub fn get_default_formatter() -> Formatter {{\n\
             formatter! {{\n"
    )
    .unwrap();

    for result in csv_reader.records() {
        let record = result.unwrap();
        let element_id = &record[element_id_pos];
        let name = &record[name_pos];
        let abstract_data_type = &record[abstract_data_type_pos];
        let data_type = match abstract_data_type {
            "octetArray" => "Bytes",
            "unsigned8" => "UnsignedInt",
            "unsigned16" => "UnsignedInt",
            "unsigned32" => "UnsignedInt",
            "unsigned64" => "UnsignedInt",
            "signed8" => "SignedInt",
            "signed16" => "SignedInt",
            "signed32" => "SignedInt",
            "signed64" => "SignedInt",
            "float32" => "Float",
            "float64" => "Float",
            "boolean" => "Bool",
            "macAddress" => "MacAddress",
            "string" => "String",
            "dateTimeSeconds" => "DateTimeSeconds",
            "dateTimeMilliseconds" => "DateTimeMilliseconds",
            "dateTimeMicroseconds" => "DateTimeMicroseconds",
            "dateTimeNanoseconds" => "DateTimeNanoseconds",
            "ipv4Address" => "Ipv4Addr",
            "ipv6Address" => "Ipv6Addr",
            // TODO: support for lists [RFC6313]
            "basicList" => continue,
            "subTemplateList" => continue,
            "subTemplateMultiList" => continue,
            "" => continue,
            d => panic!("Unknown abstract data type {d}!"),
        };

        writeln!(
            out_file,
            "        (0, {element_id}) => (\"{name}\", {data_type}), // {abstract_data_type}"
        )
        .unwrap();
        //out_file.write("");
    }

    write!(out_file, "    }}\n}}").unwrap();
}
