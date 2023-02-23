use ahash::HashMap;

use crate::DataRecordType;

/// mapping of (enterprise_number, information_element_identifier) -> (name, type)
pub type Formatter = HashMap<(u32, u16), (&'static str, DataRecordType)>;

/// slightly nicer syntax to make a `Formatter`
#[macro_export]
macro_rules! formatter {
    { $(($key:expr, $id:expr) => ($string:expr, $value:ident)),+ $(,)? } => {
        HashMap::from_iter([
            $( ((($key, $id), ($string, DataRecordType::$value))), )+
        ])
    };
}

/// extend an existing `Formatter`
#[macro_export]
macro_rules! extend_formatter(
    { $formatter:ident += { $(($key:expr, $id:expr) => ($string:expr, $value:ident)),+ $(,)? } } => {
        $formatter.extend([
            $( ((($key, $id), ($string, DataRecordType::$value))), )+
        ])
    };
);

include!(concat!(env!("OUT_DIR"), "/ipfix-information-elements.rs"));
