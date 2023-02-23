use std::{
    cell::RefCell,
    rc::Rc,
    sync::{Arc, RwLock},
};

use ahash::HashMap;

use crate::{
    information_elements::Formatter, DataRecordKey, DataRecordType, FieldSpecifier, OptionsTemplateRecord,
    TemplateRecord,
};

#[derive(Clone, Debug)]
pub struct ExpandedFieldSpecifier {
    pub name: DataRecordKey,
    pub ty: DataRecordType,
    pub enterprise_number: Option<u32>,
    pub information_element_identifier: u16,
    pub field_length: u16,
}

impl ExpandedFieldSpecifier {
    /// Look up a DataRecordKey and DataRecordType for this
    /// information element from the formatter. If not present,
    /// returns Unrecognized/Bytes.
    fn from_field_spec(field_spec: &FieldSpecifier, formatter: &Formatter) -> Self {
        let (name, ty) = match formatter.get(&(
            field_spec.enterprise_number.unwrap_or(0),
            field_spec.information_element_identifier,
        )) {
            Some((name, ty)) => (DataRecordKey::Str(name), ty),
            None => (
                DataRecordKey::Unrecognized(field_spec.clone()),
                // TODO: this is probably not technically correct
                &DataRecordType::Bytes,
            ),
        };

        Self {
            name,
            ty: *ty,
            enterprise_number: field_spec.enterprise_number,
            information_element_identifier: field_spec.information_element_identifier,
            field_length: field_spec.field_length,
        }
    }
}

#[derive(Clone, Debug)]
pub enum Template {
    Template(Vec<ExpandedFieldSpecifier>),
    OptionsTemplate(Vec<ExpandedFieldSpecifier>),
}

pub trait TemplateStorage {
    fn get_template(&self, template_id: u16) -> Option<Template>;
    fn insert_template(&self, template_id: u16, template: Template);

    fn insert_template_records(&self, template_records: &[TemplateRecord], formatter: &Formatter) {
        for template in template_records {
            let expanded_template = Template::Template(
                template
                    .field_specifiers
                    .iter()
                    .map(|field_spec| {
                        ExpandedFieldSpecifier::from_field_spec(field_spec, formatter)
                    })
                    .collect(),
            );

            self.insert_template(template.template_id, expanded_template);
        }
    }

    // TODO: these should probably be treated differently
    fn insert_options_template_records(
        &self,
        template_records: &[OptionsTemplateRecord],
        formatter: &Formatter,
    ) {
        for template in template_records {
            let expanded_template = Template::OptionsTemplate(
                template
                    .field_specifiers
                    .iter()
                    .map(|field_spec| {
                        ExpandedFieldSpecifier::from_field_spec(field_spec, formatter)
                    })
                    .collect(),
            );
            self.insert_template(template.template_id, expanded_template);
        }
    }
}

impl TemplateStorage for RefCell<HashMap<u16, Template>> {
    fn get_template(&self, template_id: u16) -> Option<Template> {
        self.borrow().get(&template_id).cloned()
    }
    fn insert_template(&self, template_id: u16, template: Template) {
        self.borrow_mut().insert(template_id, template);
    }
}

impl TemplateStorage for Arc<RwLock<HashMap<u16, Template>>> {
    fn get_template(&self, template_id: u16) -> Option<Template> {
        self.read().unwrap().get(&template_id).cloned()
    }
    fn insert_template(&self, template_id: u16, template: Template) {
        self.write().unwrap().insert(template_id, template);
    }
}

pub type TemplateStore = Rc<dyn TemplateStorage>;
