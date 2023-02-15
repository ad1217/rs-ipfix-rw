//! Read-write implementation of the IPFIX Protocol, see <https://www.rfc-editor.org/rfc/rfc7011>

use std::{
    cell::RefCell,
    net::{Ipv4Addr, Ipv6Addr},
    rc::Rc,
};

use ahash::{HashMap, HashMapExt};
use binrw::{
    binrw, binwrite, count,
    io::{Read, Seek, Write},
    until_eof, BinRead, BinReaderExt, BinResult, BinWrite, BinWriterExt, Endian,
};

pub mod properties;
mod util;
use crate::properties::Formatter;
use crate::util::{until_limit, WriteSize};

// TODO: add support for option templates
pub type Templates = Rc<RefCell<HashMap<u16, Vec<FieldSpecifier>>>>;

/// <https://www.rfc-editor.org/rfc/rfc7011#section-3.1>
#[binrw]
#[brw(big, magic = 10u16)]
#[brw(import( templates: Templates, formatter: Rc<Formatter>))]
#[derive(PartialEq, Debug)]
pub struct Message {
    #[br(temp)]
    #[bw(try_calc = self.write_size((templates.clone(), formatter.clone())))]
    length: u16,
    pub export_time: u32,
    pub sequence_number: u32,
    pub observation_domain_id: u32,
    #[br(parse_with = until_eof)]
    #[brw(args(templates, formatter))]
    pub sets: Vec<Set>,
}

impl WriteSize for Message {
    type Arg = (Templates, Rc<Formatter>);

    fn write_size(&self, arg: Self::Arg) -> Result<u16, String> {
        Ok(16 + self.sets.write_size(arg)?)
    }
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
#[brw(big, import( templates: Templates, formatter: Rc<Formatter> ))]
#[derive(PartialEq, Debug)]
pub struct Set {
    #[br(temp)]
    #[bw(calc = records.set_id())]
    set_id: u16,
    #[br(temp)]
    #[br(assert(length > 4))]
    #[bw(try_calc = self.write_size((templates.clone(), formatter.clone())))]
    length: u16,
    // TODO: padding
    #[br(args(set_id, length - 4, templates, formatter))]
    #[bw(args(templates, formatter))]
    pub records: Records,
}

impl WriteSize for Set {
    type Arg = (Templates, Rc<Formatter>);

    fn write_size(&self, arg: Self::Arg) -> Result<u16, String> {
        Ok(4 + self.records.write_size(arg)?)
    }
}

/// <https://www.rfc-editor.org/rfc/rfc7011.html#section-3.4>
#[binrw]
#[brw(big)]
#[br(import ( set_id: u16, length: u16, templates: Templates, formatter: Rc<Formatter> ))]
#[bw(import ( templates: Templates, formatter: Rc<Formatter> ))]
#[derive(PartialEq, Debug)]
pub enum Records {
    #[br(pre_assert(set_id == 2))]
    Template(
        #[br(map = |x: Vec<TemplateRecord>| {insert_template_records(templates.clone(), x.as_slice()); x}, parse_with = until_limit(length.into()))]
         Vec<TemplateRecord>,
    ),
    #[br(pre_assert(set_id == 3))]
    OptionsTemplate(#[br(parse_with = until_limit(length.into()))] Vec<OptionsTemplateRecord>),
    #[br(pre_assert(set_id > 255, "Set IDs 0-1 and 4-255 are reserved [set_id: {set_id}]"))]
    Data {
        #[br(calc = set_id)]
        #[bw(ignore)]
        set_id: u16,
        #[br(parse_with = until_limit(length.into()))]
        #[br(args(set_id, templates, formatter))]
        #[bw(args(*set_id, templates, formatter))]
        data: Vec<DataRecord>,
    },
}

fn insert_template_records(templates: Templates, new_templates: &[TemplateRecord]) {
    let mut templates = templates.borrow_mut();
    for template in new_templates {
        templates.insert(template.template_id, template.field_specifiers.clone());
    }
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

impl WriteSize for Records {
    type Arg = (Templates, Rc<Formatter>);

    fn write_size(&self, (templates, formatter): Self::Arg) -> Result<u16, String> {
        match self {
            Records::Template(records) => records.write_size(()),
            Records::OptionsTemplate(records) => records.write_size(()),
            Records::Data { data, .. } => data.write_size((self.set_id(), templates, formatter)),
        }
    }
}

/// <https://www.rfc-editor.org/rfc/rfc7011#section-3.4.1>
#[binrw]
#[brw(big)]
#[derive(PartialEq, Debug)]
#[br(assert(template_id > 255, "Template IDs 0-255 are reserved [template_id: {template_id}]"))]
pub struct TemplateRecord {
    pub template_id: u16,
    #[br(temp)]
    #[bw(try_calc = field_specifiers.len().try_into())]
    field_count: u16,
    #[br(count = field_count)]
    pub field_specifiers: Vec<FieldSpecifier>,
}

impl WriteSize for TemplateRecord {
    type Arg = ();

    fn write_size(&self, _: Self::Arg) -> Result<u16, String> {
        Ok(4 + self.field_specifiers.write_size(())?)
    }
}

/// <https://www.rfc-editor.org/rfc/rfc7011#section-3.4.2>
#[binrw]
#[brw(big)]
#[derive(PartialEq, Debug)]
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

impl WriteSize for OptionsTemplateRecord {
    type Arg = ();

    fn write_size(&self, _: Self::Arg) -> Result<u16, String> {
        Ok(6 + self.field_specifiers.write_size(())?)
    }
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
    /// Look up a DataRecordKey and DataRecordType for this
    /// information element from the formatter. If not present,
    /// returns Unrecognized/Bytes.
    fn key_and_type<'a>(&self, formatter: &'a Formatter) -> (DataRecordKey, &'a DataRecordType) {
        match formatter.get(&(
            self.enterprise_number.unwrap_or(0),
            self.information_element_identifier,
        )) {
            Some((name, ty)) => (DataRecordKey::Str(name), ty),
            None => (
                DataRecordKey::Unrecognized(self.clone()),
                // TODO: this is probably not technically correct
                &DataRecordType::Bytes,
            ),
        }
    }
}

impl WriteSize for FieldSpecifier {
    type Arg = ();

    fn write_size(&self, _: Self::Arg) -> Result<u16, String> {
        Ok(4 + match self.enterprise_number {
            Some(_) => 4,
            None => 0,
        })
    }
}

/// <https://www.rfc-editor.org/rfc/rfc7011#section-3.4.3>
#[derive(PartialEq, Debug)]
pub struct DataRecord {
    pub values: HashMap<DataRecordKey, DataRecordValue>,
}

impl BinRead for DataRecord {
    type Args<'a> = (u16, Templates, Rc<Formatter>);

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        endian: Endian,
        (set_id, templates, formatter): Self::Args<'_>,
    ) -> BinResult<Self> {
        let templates = templates.borrow();
        let template = templates.get(&set_id).ok_or(binrw::Error::AssertFail {
            pos: reader.stream_position()?,
            message: format!("Missing template for set id {set_id}"),
        })?;

        let mut values = HashMap::with_capacity(template.len());
        for field_spec in template.iter() {
            // TODO: should read whole field length according to template, regardless of type
            let (key, ty) = field_spec.key_and_type(&formatter);
            let value = reader.read_type_args(endian, (*ty, field_spec.field_length))?;

            values.insert(key, value);
        }
        Ok(Self { values })
    }
}

impl BinWrite for DataRecord {
    type Args<'a> = (u16, Templates, Rc<Formatter>);

    fn write_options<W: Write + Seek>(
        &self,
        writer: &mut W,
        endian: Endian,
        (set_id, templates, formatter): Self::Args<'_>,
    ) -> BinResult<()> {
        let templates = templates.borrow();
        let template = templates.get(&set_id).ok_or(binrw::Error::AssertFail {
            pos: writer.stream_position()?,
            message: format!("Missing template for set id {set_id}"),
        })?;

        // TODO: should check if all keys are used?
        for field_spec in template {
            // TODO: check template type vs actual type?
            let (key, _ty) = field_spec.key_and_type(&formatter);

            let value = self
                .values
                .get(&key)
                // TODO: better error type?
                .ok_or(binrw::Error::AssertFail {
                    pos: writer.stream_position()?,
                    message: "Missing field templated in template".into(),
                })?;

            writer.write_type_args(value, endian, (field_spec.field_length,))?;
        }
        Ok(())
    }
}

impl WriteSize for DataRecord {
    type Arg = (u16, Templates, Rc<Formatter>);

    fn write_size(&self, (set_id, templates, formatter): Self::Arg) -> Result<u16, String> {
        let templates = templates.borrow();
        let template = templates
            .get(&set_id)
            .ok_or(format!("Missing template for set id {set_id}"))?;

        let mut size = 0;

        // TODO: should check if all keys are used?
        for field_spec in template {
            // TODO: check template type vs actual type?
            let (key, _ty) = field_spec.key_and_type(&formatter);

            let value = self
                .values
                .get(&key)
                // TODO: better error type?
                .ok_or("Missing field templated in template".to_string())?;

            // TODO: should pass by reference
            size += value.write_size(field_spec.clone())?;
        }

        Ok(size)
    }
}

#[derive(PartialEq, Eq, Hash, Debug)]
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
#[derive(PartialEq, Debug)]
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

impl WriteSize for DataRecordValue {
    type Arg = FieldSpecifier;

    fn write_size(&self, field_spec: Self::Arg) -> Result<u16, String> {
        // variable length field
        Ok(if field_spec.field_length == u16::MAX {
            let len = match self {
                DataRecordValue::Bytes(bytes) => bytes.len(),
                DataRecordValue::String(string) => string.len(),
                _ => Err("Non variable length field!")?,
            };

            let max_len = u16::MAX - 3;
            if len > max_len.into() {
                Err("Tried to determine length for a variable length element which is larger than u16::MAX - 3")?
            } else if len < 255 {
                (len + 1) as u16
            } else {
                (len + 3) as u16
            }
        // fixed length field
        } else {
            field_spec.field_length
        })
    }
}
