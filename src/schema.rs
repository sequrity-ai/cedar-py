use cedar_policy::{Schema, ValidationMode, Validator};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use std::str::FromStr;

/// A Cedar schema for policy validation.
///
/// Schemas define the structure of entities, actions, and the relationships
/// between them, allowing policies to be validated for correctness.
#[pyclass]
pub struct CedarSchema {
    schema: Schema,
}

#[pymethods]
impl CedarSchema {
    /// Create a schema from Cedar schema JSON/text.
    ///
    /// Args:
        ///     schema_text (str): The schema definition in Cedar schema format
    ///
    /// Raises:
    ///     ValueError: If the schema is invalid
    ///
    /// Example:
    ///     >>> schema_text = '''
    ///     ... entity User, Group;
    ///     ... entity Document {
    ///     ...     owner: User,
    ///     ... };
    ///     ... action view appliesTo {
    ///     ...     principal: [User, Group],
    ///     ...     resource: [Document]
    ///     ... };
    ///     ... '''
    ///     >>> schema = CedarSchema(schema_text)
    #[new]
    fn new(schema_text: &str) -> PyResult<Self> {
        let schema = Schema::from_str(schema_text)
            .map_err(|e| PyValueError::new_err(format!("Invalid schema: {}", e)))?;

        Ok(CedarSchema { schema })
    }

    /// String representation of the schema.
    fn __repr__(&self) -> String {
        "CedarSchema(...)".to_string()
    }
}

impl CedarSchema {
    /// Get the internal Cedar schema (for use within the library).
    pub(crate) fn get_schema(&self) -> &Schema {
        &self.schema
    }
}

/// Validate policies against a schema.
///
/// Args:
///     policies (PolicySet): The policy set to validate
///     schema (CedarSchema): The schema to validate against
///     mode (str, optional): Validation mode - "strict" or "permissive" (default: "strict")
///
/// Returns:
///     list: A list of validation error messages (empty if valid)
///
/// Example:
///     >>> errors = validate_policies(policies, schema)
///     >>> if errors:
///     ...         for error in errors:
///     ...             print(f"Validation error: {error}")
///     ... else:
///     ...         print("All policies are valid!")
#[pyfunction]
#[pyo3(signature = (policies, schema, mode="strict"))]
pub fn validate_policies(
    policies: &crate::policy_set::PolicySet,
    schema: &CedarSchema,
    mode: &str,
) -> PyResult<Vec<String>> {
    // Parse validation mode - Cedar 4.x only has Strict mode
    let validation_mode = match mode {
        "strict" => ValidationMode::Strict,
        _ => {
            return Err(PyValueError::new_err(format!(
                "Invalid validation mode '{}'. Currently only 'strict' is supported",
                mode
            )))
        }
    };

    // Create validator
    let validator = Validator::new(schema.get_schema().clone());

    // Get the Cedar policy set
    let policy_set = policies.get_cedar_policy_set();

    // Validate
    let result = validator.validate(&policy_set, validation_mode);

    // Collect errors and warnings
    let mut messages = Vec::new();

    for error in result.validation_errors() {
        messages.push(format!("Error: {}", error));
    }

    for warning in result.validation_warnings() {
        messages.push(format!("Warning: {}", warning));
    }

    Ok(messages)
}
