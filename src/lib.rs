#![doc = include_str!("../README.md")]

pub mod information_elements;
pub mod parser;
pub mod template_store;
mod util;

use std::{io::Cursor, rc::Rc};

use binrw::{BinRead, BinResult};
use information_elements::Formatter;
use template_store::TemplateStore;

use crate::parser::Message;

pub fn parse_ipfix_message<T: AsRef<[u8]>>(
    buf: &T,
    templates: TemplateStore,
    formatter: Rc<Formatter>,
) -> BinResult<Message> {
    Message::read_args(&mut Cursor::new(buf), (templates, formatter))
}
