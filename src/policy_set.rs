use cedar_policy::{Policy, PolicySet as CedarPolicySet};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use std::collections::HashMap;
use std::str::FromStr;

/// A collection of Cedar policies.
///
/// This class represents a set of Cedar policies that can be evaluated
/// together for authorization decisions.
#[pyclass]
pub struct PolicySet {
    policies: HashMap<String, String>, // Store policy text instead of parsed Policy
}

#[pymethods]
impl PolicySet {
    /// Create a new empty policy set.
    #[new]
    fn new() -> Self {
        PolicySet {
            policies: HashMap::new(),
        }
    }

    /// Add a policy to the set.
    ///
    /// Args:
    ///     policy_id (str): Unique identifier for the policy
    ///     policy_text (str): The Cedar policy text
    ///
    /// Raises:
    ///     ValueError: If the policy text is invalid
    fn add_policy(&mut self, policy_id: String, policy_text: &str) -> PyResult<()> {
        // Validate the policy by parsing it
        Policy::from_str(policy_text)
            .map_err(|e| PyValueError::new_err(format!("Invalid policy: {}", e)))?;

        // Store the original text
        self.policies.insert(policy_id, policy_text.to_string());
        Ok(())
    }

    /// Get a policy by its ID.
    ///
    /// Args:
    ///     policy_id (str): The policy identifier
    ///
    /// Returns:
    ///     str or None: The policy text, or None if not found
    fn get_policy(&self, policy_id: &str) -> Option<String> {
        self.policies.get(policy_id).cloned()
    }

    /// Get the number of policies in the set.
    ///
    /// Returns:
    ///     int: The number of policies
    fn __len__(&self) -> usize {
        self.policies.len()
    }

    /// String representation of the policy set.
    fn __repr__(&self) -> String {
        format!("PolicySet(policies={})", self.policies.len())
    }
}

impl PolicySet {
    /// Convert to a Cedar PolicySet (internal use).
    pub(crate) fn get_cedar_policy_set(&self) -> CedarPolicySet {
        // Build a single policy set text with all policies annotated with their IDs
        let mut combined_policies = String::new();

        for (id, policy_text) in &self.policies {
            // Add an @id annotation before each policy
            combined_policies.push_str(&format!("@id(\"{}\")\n{}\n\n", id, policy_text));
        }

        // Parse the combined policy set
        match CedarPolicySet::from_str(&combined_policies) {
            Ok(policy_set) => policy_set,
            Err(e) => {
                eprintln!("Warning: Failed to parse policy set: {}", e);
                CedarPolicySet::new()
            }
        }
    }
}
