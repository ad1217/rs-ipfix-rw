//! Read-write implementation of the IPFIX Protocol, see <https://www.rfc-editor.org/rfc/rfc7011>

use std::{
    net::{Ipv4Addr, Ipv6Addr},
    rc::Rc,
};

use ahash::{HashMap, HashMapExt};
use binrw::{
    binrw, binwrite, count,
    io::{Read, Seek, Write},
    until_eof, BinRead, BinReaderExt, BinResult, BinWrite, BinWriterExt, Endian,
};

pub mod information_elements;
pub mod template_store;
mod util;
use crate::information_elements::Formatter;
use crate::template_store::{Template, TemplateStore};
use crate::util::{stream_position, until_limit, write_position_at};

/// <https://www.rfc-editor.org/rfc/rfc7011#section-3.1>
#[binrw]
#[brw(big, magic = 10u16)]
#[br(import( templates: TemplateStore, formatter: Rc<Formatter>))]
#[bw(import( templates: TemplateStore, formatter: Rc<Formatter>, alignment: u8))]
#[bw(stream = s)]
#[derive(PartialEq, Clone, Debug)]
pub struct Message {
    #[br(temp)]
    // store offset for later updating
    #[bw(try_calc = stream_position(s))]
    length: u16,
    pub export_time: u32,
    pub sequence_number: u32,
    pub observation_domain_id: u32,
    #[br(parse_with = until_eof)]
    #[br(args(templates, formatter))]
    #[bw(args(templates, formatter, alignment))]
    pub sets: Vec<Set>,
    // jump back to length and set by current position
    #[br(temp)]
    #[bw(restore_position, try_calc = write_position_at(s, length, 0))]
    _temp: (),
}

impl Message {
    pub fn iter_template_records(&self) -> impl Iterator<Item = &TemplateRecord> {
        self.sets
            .iter()
            .filter_map(|set| match &set.records {
                Records::Template(templates) => Some(templates),
                _ => None,
            })
            .flatten()
    }

    pub fn iter_options_template_records(&self) -> impl Iterator<Item = &OptionsTemplateRecord> {
        self.sets
            .iter()
            .filter_map(|set| match &set.records {
                Records::OptionsTemplate(templates) => Some(templates),
                _ => None,
            })
            .flatten()
    }

    pub fn iter_data_records(&self) -> impl Iterator<Item = &DataRecord> {
        self.sets
            .iter()
            .filter_map(|set| match &set.records {
                Records::Data { data, .. } => Some(data),
                _ => None,
            })
            .flatten()
    }
}

/// <https://www.rfc-editor.org/rfc/rfc7011#section-3.3>
#[binrw]
#[br(big, import( templates: TemplateStore, formatter: Rc<Formatter> ))]
#[bw(big, stream = s, import( templates: TemplateStore, formatter: Rc<Formatter>, alignment: u8 ))]
#[derive(PartialEq, Clone, Debug)]
pub struct Set {
    #[br(temp)]
    #[bw(calc = records.set_id())]
    set_id: u16,
    #[br(temp)]
    #[br(assert(length > 4, "invalid set length: [{length} <= 4]"))]
    // store offset for later updating
    #[bw(try_calc = stream_position(s))]
    length: u16,
    #[br(pad_size_to = length - 4)]
    #[br(args(set_id, length - 4, templates, formatter))]
    #[bw(align_after = alignment)]
    #[bw(args(templates, formatter))]
    pub records: Records,
    // jump back to length and set by current position
    #[br(temp)]
    #[bw(restore_position, try_calc = write_position_at(s, length, length - 2))]
    _temp: (),
}

/// <https://www.rfc-editor.org/rfc/rfc7011.html#section-3.4>
#[binrw]
#[brw(big)]
#[br(import ( set_id: u16, length: u16, templates: TemplateStore, formatter: Rc<Formatter> ))]
#[bw(import ( templates: TemplateStore, formatter: Rc<Formatter> ))]
#[derive(PartialEq, Clone, Debug)]
pub enum Records {
    #[br(pre_assert(set_id == 2))]
    Template(
        #[br(map = |x: Vec<TemplateRecord>| {templates.insert_template_records(x.as_slice(), &formatter); x})]
        #[br(parse_with = until_limit(length.into()))]
        Vec<TemplateRecord>,
    ),
    #[br(pre_assert(set_id == 3))]
    OptionsTemplate(
        #[br(map = |x: Vec<OptionsTemplateRecord>| {templates.insert_options_template_records(x.as_slice(), &formatter); x})]
        #[br(parse_with = until_limit(length.into()))]
        Vec<OptionsTemplateRecord>,
    ),
    #[br(pre_assert(set_id > 255, "Set IDs 0-1 and 4-255 are reserved [set_id: {set_id}]"))]
    Data {
        #[br(calc = set_id)]
        #[bw(ignore)]
        set_id: u16,
        #[br(parse_with = until_limit(length.into()))]
        #[br(args(set_id, templates))]
        #[bw(args(*set_id, templates))]
        data: Vec<DataRecord>,
    },
}

impl Records {
    fn set_id(&self) -> u16 {
        match self {
            Self::Template(_) => 2,
            Self::OptionsTemplate(_) => 3,
            Self::Data { set_id, data: _ } => *set_id,
        }
    }
}

/// <https://www.rfc-editor.org/rfc/rfc7011#section-3.4.1>
#[binrw]
#[brw(big)]
#[derive(PartialEq, Clone, Debug)]
#[br(assert(template_id > 255, "Template IDs 0-255 are reserved [template_id: {template_id}]"))]
pub struct TemplateRecord {
    pub template_id: u16,
    #[br(temp)]
    #[bw(try_calc = field_specifiers.len().try_into())]
    field_count: u16,
    #[br(count = field_count)]
    pub field_specifiers: Vec<FieldSpecifier>,
}

/// <https://www.rfc-editor.org/rfc/rfc7011#section-3.4.2>
#[binrw]
#[brw(big)]
#[derive(PartialEq, Clone, Debug)]
#[br(assert(template_id > 255, "Template IDs 0-255 are reserved [template_id: {template_id}]"))]
pub struct OptionsTemplateRecord {
    pub template_id: u16,
    #[br(temp)]
    #[bw(try_calc = field_specifiers.len().try_into())]
    field_count: u16,
    // TODO
    pub scope_field_count: u16,
    #[br(count = field_count)]
    pub field_specifiers: Vec<FieldSpecifier>,
}

/// <https://www.rfc-editor.org/rfc/rfc7011#section-3.2>
#[binrw]
#[brw(big)]
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct FieldSpecifier {
    #[br(temp)]
    #[bw(calc = information_element_identifier | (u16::from(enterprise_number.is_some()) << 15))]
    raw_information_element_identifier: u16,
    #[br(calc = raw_information_element_identifier & (u16::MAX >> 1))]
    #[bw(ignore)]
    pub information_element_identifier: u16,
    pub field_length: u16,
    #[br(if(raw_information_element_identifier >> 15 == 1))]
    pub enterprise_number: Option<u32>,
}

impl FieldSpecifier {
    pub fn new(
        enterprise_number: Option<u32>,
        information_element_identifier: u16,
        field_length: u16,
    ) -> Self {
        Self {
            information_element_identifier,
            field_length,
            enterprise_number,
        }
    }
}

/// <https://www.rfc-editor.org/rfc/rfc7011#section-3.4.3>
#[derive(PartialEq, Clone, Debug)]
pub struct DataRecord {
    pub values: HashMap<DataRecordKey, DataRecordValue>,
}

/// slightly nicer syntax to make a `DataRecord`
#[macro_export]
macro_rules! data_record {
    { $($key:literal: $type:ident($value:expr)),+ $(,)? } => {
        DataRecord {
            values: HashMap::from_iter([
                $( ((DataRecordKey::Str($key), DataRecordValue::$type($value))), )+
            ])
        }
    };
}

impl BinRead for DataRecord {
    type Args<'a> = (u16, TemplateStore);

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        endian: Endian,
        (set_id, templates): Self::Args<'_>,
    ) -> BinResult<Self> {
        let template = templates
            .get_template(set_id)
            .ok_or(binrw::Error::AssertFail {
                pos: reader.stream_position()?,
                message: format!("Missing template for set id {set_id}"),
            })?;

        // TODO: should these be handled differently?
        let field_specifiers = match template {
            Template::Template(field_specifiers) => field_specifiers,
            Template::OptionsTemplate(field_specifiers) => field_specifiers,
        };

        let mut values = HashMap::with_capacity(field_specifiers.len());
        for field_spec in field_specifiers.iter() {
            // TODO: should read whole field length according to template, regardless of type
            let value = reader.read_type_args(endian, (field_spec.ty, field_spec.field_length))?;

            values.insert(field_spec.name.clone(), value);
        }
        Ok(Self { values })
    }
}

impl BinWrite for DataRecord {
    type Args<'a> = (u16, TemplateStore);

    fn write_options<W: Write + Seek>(
        &self,
        writer: &mut W,
        endian: Endian,
        (set_id, templates): Self::Args<'_>,
    ) -> BinResult<()> {
        let template = templates
            .get_template(set_id)
            .ok_or(binrw::Error::AssertFail {
                pos: writer.stream_position()?,
                message: format!("Missing template for set id {set_id}"),
            })?;

        let field_specifiers = match template {
            Template::Template(field_specifiers) => field_specifiers,
            Template::OptionsTemplate(field_specifiers) => field_specifiers,
        };

        // TODO: should check if all keys are used?
        for field_spec in field_specifiers {
            // TODO: check template type vs actual type?
            let value = self
                .values
                .get(&field_spec.name)
                // TODO: better error type?
                .ok_or(binrw::Error::AssertFail {
                    pos: writer.stream_position()?,
                    message: format!(
                        "Field in template missing from data [{:?}]",
                        field_spec.name
                    ),
                })?;

            writer.write_type_args(value, endian, (field_spec.field_length,))?;
        }
        Ok(())
    }
}

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub enum DataRecordKey {
    Str(&'static str),
    Unrecognized(FieldSpecifier),
    Err(String),
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum DataRecordType {
    UnsignedInt,
    SignedInt,
    Float,
    Bool,
    MacAddress,
    Bytes,
    String,
    DateTimeSeconds,
    DateTimeMilliseconds,
    DateTimeMicroseconds,
    DateTimeNanoseconds,
    Ipv4Addr,
    Ipv6Addr,
}

#[binwrite]
#[bw(big)]
#[bw(import( length: u16 ))]
#[derive(PartialEq, Clone, Debug)]
pub enum DataRecordValue {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
    Bool(#[bw(map = |&x| -> u8 {if x {1} else {2} })] bool),

    MacAddress([u8; 6]),

    // TODO: same logic as variable length string
    Bytes(
        #[bw(if(length == u16::MAX), calc = if self_2.len() < 255 { self_2.len() as u8 } else { 255 })]
         u8,
        #[bw(if(length == u16::MAX && self_2.len() >= 255), try_calc = self_2.len().try_into())]
        u16,
        Vec<u8>,
    ),
    String(
        #[bw(if(length == u16::MAX), calc = if self_2.len() < 255 { self_2.len() as u8 } else { 255 })]
         u8,
        #[bw(if(length == u16::MAX && self_2.len() >= 255), try_calc = self_2.len().try_into())]
        u16,
        #[bw(map = |x| x.as_bytes())] String,
    ),

    DateTimeSeconds(u32),
    DateTimeMilliseconds(u64),
    DateTimeMicroseconds(u64),
    DateTimeNanoseconds(u64),

    Ipv4Addr(#[bw(map = |&x| -> u32 {x.into()})] Ipv4Addr),
    Ipv6Addr(#[bw(map = |&x| -> u128 {x.into()})] Ipv6Addr),
}

fn read_variable_length<R: Read + Seek>(
    reader: &mut R,
    endian: Endian,
    length: u16,
) -> BinResult<Vec<u8>> {
    let actual_length = if length == u16::MAX {
        let var_length: u8 = reader.read_type(endian)?;
        if var_length == 255 {
            let var_length_ext: u16 = reader.read_type(endian)?;
            var_length_ext
        } else {
            var_length.into()
        }
    } else {
        length
    };
    count(actual_length.into())(reader, endian, ())
}

impl BinRead for DataRecordValue {
    type Args<'a> = (DataRecordType, u16);

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        endian: Endian,
        (ty, length): Self::Args<'_>,
    ) -> BinResult<Self> {
        // TODO: length shouldn't actually change the data type, technically
        Ok(match (ty, length) {
            (DataRecordType::UnsignedInt, 1) => DataRecordValue::U8(reader.read_type(endian)?),
            (DataRecordType::UnsignedInt, 2) => DataRecordValue::U16(reader.read_type(endian)?),
            (DataRecordType::UnsignedInt, 4) => DataRecordValue::U32(reader.read_type(endian)?),
            (DataRecordType::UnsignedInt, 8) => DataRecordValue::U64(reader.read_type(endian)?),
            (DataRecordType::SignedInt, 1) => DataRecordValue::I8(reader.read_type(endian)?),
            (DataRecordType::SignedInt, 2) => DataRecordValue::I16(reader.read_type(endian)?),
            (DataRecordType::SignedInt, 4) => DataRecordValue::I32(reader.read_type(endian)?),
            (DataRecordType::SignedInt, 8) => DataRecordValue::I64(reader.read_type(endian)?),
            (DataRecordType::Float, 4) => DataRecordValue::F32(reader.read_type(endian)?),
            (DataRecordType::Float, 8) => DataRecordValue::F64(reader.read_type(endian)?),
            // TODO: technically 1=>true, 2=>false, others undefined
            (DataRecordType::Bool, 1) => DataRecordValue::Bool(u8::read(reader).map(|x| x == 1)?),
            (DataRecordType::MacAddress, 6) => {
                DataRecordValue::MacAddress(reader.read_type(endian)?)
            }

            (DataRecordType::Bytes, _) => {
                DataRecordValue::Bytes(read_variable_length(reader, endian, length)?)
            }
            (DataRecordType::String, _) => DataRecordValue::String(
                match String::from_utf8(read_variable_length(reader, endian, length)?) {
                    Ok(s) => s,
                    Err(e) => {
                        return Err(binrw::Error::Custom {
                            pos: reader.stream_position()?,
                            err: Box::new(e),
                        });
                    }
                },
            ),

            (DataRecordType::DateTimeSeconds, 4) => {
                DataRecordValue::DateTimeSeconds(reader.read_type(endian)?)
            }

            (DataRecordType::DateTimeMilliseconds, 8) => {
                DataRecordValue::DateTimeMilliseconds(reader.read_type(endian)?)
            }

            (DataRecordType::DateTimeMicroseconds, 8) => {
                DataRecordValue::DateTimeMicroseconds(reader.read_type(endian)?)
            }

            (DataRecordType::DateTimeNanoseconds, 8) => {
                DataRecordValue::DateTimeNanoseconds(reader.read_type(endian)?)
            }

            (DataRecordType::Ipv4Addr, 4) => {
                DataRecordValue::Ipv4Addr(u32::read_be(reader)?.into())
            }

            (DataRecordType::Ipv6Addr, 16) => {
                DataRecordValue::Ipv6Addr(u128::read_be(reader)?.into())
            }
            _ => Err(binrw::Error::AssertFail {
                pos: reader.stream_position()?,
                message: format!("Invalid type/length pair: {ty:?} {length}"),
            })?,
        })
    }
}
