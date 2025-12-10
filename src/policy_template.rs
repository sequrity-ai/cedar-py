use cedar_policy::{EntityUid, Template};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::collections::HashMap;
use std::str::FromStr;

/// A Cedar policy template.
///
/// Policy templates allow you to define reusable policy patterns with slots
/// that can be filled in when instantiating the template. This is useful for
/// creating role-based or attribute-based access control policies.
///
/// Templates use the `?principal` and `?resource` syntax for slots that must
/// be filled when creating a template-linked policy.
///
/// Example:
///     >>> template = PolicyTemplate("template1", '''
///     ...     permit(
///     ...         principal == ?principal,
///     ...         action == Action::"view",
///     ...         resource == ?resource
///     ...     );
///     ... ''')
#[pyclass]
pub struct PolicyTemplate {
    template_id: String,
    template_text: String,
}

#[pymethods]
impl PolicyTemplate {
    /// Create a new policy template.
    ///
    /// Args:
    ///     template_id (str): Unique identifier for the template
    ///     template_text (str): The Cedar policy template text with slots
    ///
    /// Raises:
    ///     ValueError: If the template text is invalid
    ///
    /// Example:
    ///     >>> template = PolicyTemplate("view-template", '''
    ///     ...     permit(
    ///     ...         principal == ?principal,
    ///     ...         action == Action::"view",
    ///     ...         resource == ?resource
    ///     ...     );
    ///     ... ''')
    #[new]
    fn new(template_id: String, template_text: &str) -> PyResult<Self> {
        // Validate the template by parsing it
        Template::from_str(template_text)
            .map_err(|e| PyValueError::new_err(format!("Invalid template: {}", e)))?;

        Ok(PolicyTemplate {
            template_id,
            template_text: template_text.to_string(),
        })
    }

    /// Get the template ID.
    ///
    /// Returns:
    ///     str: The template identifier
    #[getter]
    fn template_id(&self) -> String {
        self.template_id.clone()
    }

    /// Get the template text.
    ///
    /// Returns:
    ///     str: The template text with slots
    #[getter]
    fn template_text(&self) -> String {
        self.template_text.clone()
    }

    /// Create a policy from this template by filling in the slots.
    ///
    /// Args:
    ///     policy_id (str): Unique identifier for the instantiated policy
    ///     slots (dict): Dictionary mapping slot names to entity UIDs
    ///                   (e.g., {"principal": 'User::"alice"', "resource": 'Document::"report"'})
    ///
    /// Returns:
    ///     tuple: A tuple of (policy_id, template_id, slots_dict) for use with PolicySet
    ///
    /// Raises:
    ///     ValueError: If slot values are invalid
    ///
    /// Example:
    ///     >>> policy = template.instantiate(
    ///     ...     "policy1",
    ///     ...     {"principal": 'User::"alice"', "resource": 'Document::"report"'}
    ///     ... )
    fn instantiate(&self, policy_id: String, slots: &Bound<'_, PyDict>) -> PyResult<(String, String, HashMap<String, String>)> {
        // Convert PyDict to HashMap
        let mut slot_map = HashMap::new();

        for (key, value) in slots.iter() {
            let key_str: String = key.extract()?;
            let value_str: String = value.extract()?;

            // Validate that the value is a valid entity UID
            EntityUid::from_str(&value_str)
                .map_err(|e| PyValueError::new_err(format!("Invalid entity UID '{}': {}", value_str, e)))?;

            slot_map.insert(key_str, value_str);
        }

        // Return the instantiation data
        Ok((policy_id, self.template_id.clone(), slot_map))
    }

    /// String representation of the template.
    fn __repr__(&self) -> String {
        format!("PolicyTemplate(id='{}', slots=...)", self.template_id)
    }
}

impl PolicyTemplate {
    /// Get the template ID (internal use).
    pub(crate) fn get_template_id(&self) -> &str {
        &self.template_id
    }

    /// Get the template text (internal use).
    pub(crate) fn get_template_text(&self) -> &str {
        &self.template_text
    }
}
