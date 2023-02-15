//! Read-write implementation of the IPFIX Protocol, see <https://www.rfc-editor.org/rfc/rfc5101>

use std::{
    cell::RefCell,
    net::{Ipv4Addr, Ipv6Addr},
    rc::Rc,
};

use ahash::{HashMap, HashMapExt};
use binrw::io::{Read, Seek, Write};
use binrw::{binrw, until_eof, BinRead, BinReaderExt, BinResult, BinWrite, BinWriterExt, Endian};

pub mod properties;
mod util;
use crate::properties::EnterpriseFormatter;
use crate::util::{until_limit, WriteSize};

// TODO: add support for option templates
pub type Templates = Rc<RefCell<HashMap<u16, Vec<FieldSpecifier>>>>;

#[binrw]
#[brw(big, magic = 10u16)]
#[brw(import( templates: Templates, formatter: Rc<EnterpriseFormatter>))]
#[derive(PartialEq, Debug)]
pub struct Message {
    #[br(temp)]
    #[bw(try_calc = self.write_size((templates.clone(), formatter.clone())))]
    pub length: u16,
    pub export_time: u32,
    pub sequence_number: u32,
    pub observation_domain_id: u32,
    #[br(parse_with = until_eof)]
    #[brw(args(templates, formatter))]
    pub sets: Vec<Set>,
}

impl WriteSize for Message {
    type Arg = (Templates, Rc<EnterpriseFormatter>);

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

/// <https://www.rfc-editor.org/rfc/rfc5101#section-3.3>
#[binrw]
#[brw(big, import( templates: Templates, formatter: Rc<EnterpriseFormatter> ))]
#[derive(PartialEq, Debug)]
pub struct Set {
    #[br(temp)]
    #[bw(calc = records.set_id())]
    set_id: u16,
    #[br(temp)]
    #[bw(try_calc = self.write_size((templates.clone(), formatter.clone())))]
    pub length: u16,
    // TODO: padding
    #[br(args(set_id, length - 4, templates, formatter))]
    #[bw(args(templates, formatter))]
    pub records: Records,
}

impl WriteSize for Set {
    type Arg = (Templates, Rc<EnterpriseFormatter>);

    fn write_size(&self, arg: Self::Arg) -> Result<u16, String> {
        Ok(4 + self.records.write_size(arg)?)
    }
}

#[binrw]
#[brw(big)]
#[br(import ( set_id: u16, length: u16, templates: Templates, formatter: Rc<EnterpriseFormatter> ))]
#[bw(import ( templates: Templates, formatter: Rc<EnterpriseFormatter> ))]
#[derive(PartialEq, Debug)]
pub enum Records {
    #[br(pre_assert(set_id == 2))]
    Template(
        #[br(map = |x: Vec<TemplateRecord>| {insert_template_records(templates.clone(), x.as_slice()); x}, parse_with = until_limit(length.into()))]
         Vec<TemplateRecord>,
    ),
    #[br(pre_assert(set_id == 3))]
    OptionsTemplate(#[br(parse_with = until_limit(length.into()))] Vec<OptionsTemplateRecord>),
    // TODO: should re-enable this assert?
    //#[br(pre_assert(set_id > 255, "Set IDs 0-1 and 4-255 are reserved [set_id: {}]", set_id))]
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
    type Arg = (Templates, Rc<EnterpriseFormatter>);

    fn write_size(&self, (templates, formatter): Self::Arg) -> Result<u16, String> {
        match self {
            Records::Template(records) => records.write_size(()),
            Records::OptionsTemplate(records) => records.write_size(()),
            Records::Data { data, .. } => data.write_size((self.set_id(), templates, formatter)),
        }
    }
}

#[binrw]
#[bw(big)]
#[derive(PartialEq, Debug)]
pub struct TemplateRecord {
    // TODO: should re-enable this assert?
    //#[br(assert(template_id > 255, "Template IDs 0-255 are reserved"))]
    pub template_id: u16,
    #[br(temp)]
    #[bw(try_calc = field_specifiers.len().try_into())]
    pub field_count: u16,
    #[br(count = field_count)]
    pub field_specifiers: Vec<FieldSpecifier>,
}

impl WriteSize for TemplateRecord {
    type Arg = ();

    fn write_size(&self, _: Self::Arg) -> Result<u16, String> {
        Ok(4 + self.field_specifiers.write_size(())?)
    }
}

#[binrw]
#[brw(big)]
#[derive(PartialEq, Debug)]
pub struct OptionsTemplateRecord {
    #[br(assert(template_id > 255, "Template IDs 0-255 are reserved"))]
    pub template_id: u16,
    #[br(temp)]
    #[bw(try_calc = field_specifiers.len().try_into())]
    pub field_count: u16,
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

/// <https://www.rfc-editor.org/rfc/rfc5101#section-3.2>
#[binrw]
#[brw(big)]
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct FieldSpecifier {
    // TODO: some more validation is probably required here
    pub information_element_identifier: u16,
    pub field_length: u16,
    #[br(if(information_element_identifier >> 15 == 1))]
    pub enterprise_number: Option<u32>,
}

impl FieldSpecifier {
    /// Look up a DataRecordKey and DataRecordType for this
    /// information element from the formatter. If not present,
    /// returns Unrecognized/Bytes.
    fn key_and_type<'a>(
        &self,
        formatter: &'a EnterpriseFormatter,
    ) -> (DataRecordKey, &'a DataRecordType) {
        match formatter
            .get(&(self.enterprise_number.unwrap_or(0)))
            .and_then(|ent| ent.get(&self.information_element_identifier))
        {
            Some((name, ty)) => (DataRecordKey::Str((*name).into()), ty),
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

#[derive(PartialEq, Debug)]
pub struct DataRecord {
    pub values: HashMap<DataRecordKey, DataRecordValue>,
}

impl BinRead for DataRecord {
    type Args<'a> = (u16, Templates, Rc<EnterpriseFormatter>);

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
            let value = reader
                .read_type_args(endian, (*ty, field_spec.field_length))
                .map_err(|e| match e {
                    // Workaround for until_eof requiring all enum match errors to be eof
                    binrw::Error::EnumErrors { variant_errors, .. }
                        if variant_errors.iter().any(|(_, err)| err.is_eof()) =>
                    {
                        binrw::Error::Io(std::io::ErrorKind::UnexpectedEof.into())
                    }
                    e => e,
                })?;
            values.insert(key, value);
        }
        Ok(Self { values })
    }
}

impl BinWrite for DataRecord {
    type Args<'a> = (u16, Templates, Rc<EnterpriseFormatter>);

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
    type Arg = (u16, Templates, Rc<EnterpriseFormatter>);

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
    Str(String),
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

#[binrw]
#[brw(big)]
#[br(import( ty: DataRecordType, length: u16 ))]
#[bw(import( length: u16 ))]
#[derive(PartialEq, Debug)]
pub enum DataRecordValue {
    // TODO: length shouldn't actually change the data type, technically
    #[br(pre_assert(ty == DataRecordType::UnsignedInt && length == 1))]
    U8(u8),
    #[br(pre_assert(ty == DataRecordType::UnsignedInt && length == 2))]
    U16(u16),
    #[br(pre_assert(ty == DataRecordType::UnsignedInt && length == 4))]
    U32(u32),
    #[br(pre_assert(ty == DataRecordType::UnsignedInt && length == 8))]
    U64(u64),
    #[br(pre_assert(ty == DataRecordType::SignedInt && length == 1))]
    I8(i8),
    #[br(pre_assert(ty == DataRecordType::SignedInt && length == 2))]
    I16(i16),
    #[br(pre_assert(ty == DataRecordType::SignedInt && length == 4))]
    I32(i32),
    #[br(pre_assert(ty == DataRecordType::SignedInt && length == 8))]
    I64(i64),
    #[br(pre_assert(ty == DataRecordType::Float && length == 4))]
    F32(f32),
    #[br(pre_assert(ty == DataRecordType::Float && length == 8))]
    F64(f64),
    #[br(pre_assert(ty == DataRecordType::Bool && length == 1))]
    Bool(
        // TODO: technically 1=>true, 2=>false, others undefined
        #[br(map = |x: u8| x == 1)]
        #[bw(map = |&x| -> u8 {if x {1} else {2} })]
        bool,
    ),

    #[br(pre_assert(ty == DataRecordType::MacAddress && length == 6))]
    MacAddress([u8; 6]),

    // TODO: same logic as variable length string
    #[br(pre_assert(ty == DataRecordType::Bytes))]
    Bytes(
        #[br(temp, if(length == u16::MAX))]
        #[bw(if(length == u16::MAX), calc = if self_2.len() < 255 { self_2.len() as u8 } else { 255 })]
        u8,
        #[br(temp, if(length == u16::MAX && self_0 == 255))]
        #[bw(if(length == u16::MAX && self_2.len() >= 255), try_calc = self_2.len().try_into())]
        u16,
        #[br(count = if length == u16::MAX { if self_0 == 255 { self_1 }  else { self_0.into() } } else { length })]
         Vec<u8>,
    ),
    #[br(pre_assert(ty == DataRecordType::String))]
    String(
        #[br(temp, if(length == u16::MAX))]
        #[bw(if(length == u16::MAX), calc = if self_2.len() < 255 { self_2.len() as u8 } else { 255 })]
        u8,
        #[br(temp, if(length == u16::MAX && self_0 == 255))]
        #[bw(if(length == u16::MAX && self_2.len() >= 255), try_calc = self_2.len().try_into())]
        u16,
        #[br(count = if length == u16::MAX { if self_0 == 255 { self_1 }  else { self_0.into() } } else { length })]
        #[br(try_map = String::from_utf8)]
        #[bw(map = |x| x.as_bytes())]
        String,
    ),

    #[br(pre_assert(ty == DataRecordType::DateTimeSeconds && length == 4))]
    DateTimeSeconds(u32),
    #[br(pre_assert(ty == DataRecordType::DateTimeMilliseconds && length == 8))]
    DateTimeMilliseconds(u64),
    #[br(pre_assert(ty == DataRecordType::DateTimeMicroseconds && length == 8))]
    DateTimeMicroseconds(u64),
    #[br(pre_assert(ty == DataRecordType::DateTimeNanoseconds && length == 8))]
    DateTimeNanoseconds(u64),

    #[br(pre_assert(ty == DataRecordType::Ipv4Addr && length == 4))]
    Ipv4Addr(
        #[br(map = |x: u32| x.into())]
        #[bw(map = |&x| -> u32 {x.into()})]
        Ipv4Addr,
    ),
    #[br(pre_assert(ty == DataRecordType::Ipv6Addr && length == 16))]
    Ipv6Addr(
        #[br(map = |x: u128| x.into())]
        #[bw(map = |&x| -> u128 {x.into()})]
        Ipv6Addr,
    ),
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
