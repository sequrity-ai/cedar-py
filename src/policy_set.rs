use cedar_policy::{EntityUid, Policy, PolicyId, PolicySet as CedarPolicySet, SlotId};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::collections::HashMap;
use std::str::FromStr;

use crate::policy_template::PolicyTemplate;

/// A collection of Cedar policies and policy templates.
///
/// This class represents a set of Cedar policies that can be evaluated
/// together for authorization decisions. It supports both regular policies
/// and template-linked policies (policies instantiated from templates).
#[pyclass]
pub struct PolicySet {
    policies: HashMap<String, String>, // Store policy text instead of parsed Policy
    templates: HashMap<String, String>, // Store template text
    template_links: HashMap<String, (String, HashMap<String, String>)>, // policy_id -> (template_id, slots)
    next_auto_id: usize, // Track next available auto-generated ID
}

#[pymethods]
impl PolicySet {
    /// Create a new empty policy set.
    #[new]
    fn new() -> Self {
        PolicySet {
            policies: HashMap::new(),
            templates: HashMap::new(),
            template_links: HashMap::new(),
            next_auto_id: 0,
        }
    }

    /// Create a new PolicySet from Cedar policy text containing multiple policies.
    ///
    /// This is a class method that parses Cedar policy set text and creates
    /// a new PolicySet instance with all the policies.
    ///
    /// Args:
    ///     policies_text (str): Cedar policy set text containing one or more policies
    ///
    /// Returns:
    ///     PolicySet: A new PolicySet instance with the parsed policies
    ///
    /// Raises:
    ///     ValueError: If the policies text is invalid
    ///
    /// Example:
    ///     >>> policies = PolicySet.from_str('''
    ///     ...     permit(principal, action, resource);
    ///     ...     forbid(principal == User::"banned", action, resource);
    ///     ... ''')
    #[classmethod]
    fn from_str(_cls: &Bound<'_, pyo3::types::PyType>, policies_text: &str) -> PyResult<Self> {
        // Parse the policy set to validate and extract individual policies
        let policy_set = CedarPolicySet::from_str(policies_text)
            .map_err(|e| PyValueError::new_err(format!("Invalid policy set: {}", e)))?;

        let mut policies_map = HashMap::new();

        // Cedar assigns auto IDs like "policy0", "policy1", etc.
        // We need to extract each policy and store it with its ID
        for policy in policy_set.policies() {
            let policy_id = policy.id().to_string();
            let policy_text = policy.to_string();

            policies_map.insert(policy_id, policy_text);
        }

        Ok(PolicySet {
            policies: policies_map.clone(),
            templates: HashMap::new(),
            template_links: HashMap::new(),
            next_auto_id: policies_map.len(),
        })
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

    /// Add multiple policies from a single text string to this PolicySet.
    ///
    /// Parses Cedar policy set text containing multiple policies and adds them all.
    /// Each policy will be assigned an auto-generated ID like "policy0", "policy1", etc.
    ///
    /// Args:
    ///     policies_text (str): Cedar policy set text containing one or more policies
    ///
    /// Returns:
    ///     list[str]: List of auto-generated policy IDs for the added policies
    ///
    /// Raises:
    ///     ValueError: If the policies text is invalid
    ///
    /// Example:
    ///     >>> policies = PolicySet()
    ///     >>> policy_ids = policies.add_policies_from_str('''
    ///     ...     permit(principal, action, resource);
    ///     ...     forbid(principal == User::"banned", action, resource);
    ///     ... ''')
    ///     >>> print(policy_ids)  # ['policy0', 'policy1']
    fn add_policies_from_str(&mut self, policies_text: &str) -> PyResult<Vec<String>> {
        // Parse the policy set to validate and extract individual policies
        let policy_set = CedarPolicySet::from_str(policies_text)
            .map_err(|e| PyValueError::new_err(format!("Invalid policy set: {}", e)))?;

        let mut added_ids = Vec::new();

        // Assign unique IDs to avoid collisions with existing policies
        for policy in policy_set.policies() {
            let policy_text = policy.to_string();

            // Generate unique ID using our counter
            let unique_id = format!("policy{}", self.next_auto_id);
            self.next_auto_id += 1;

            self.policies.insert(unique_id.clone(), policy_text);
            added_ids.push(unique_id);
        }

        Ok(added_ids)
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

    /// Add a policy template to the set.
    ///
    /// Args:
    ///     template (PolicyTemplate): The policy template to add
    ///
    /// Example:
    ///     >>> template = PolicyTemplate("view-template", '''
    ///     ...     permit(
    ///     ...         principal == ?principal,
    ///     ...         action == Action::"view",
    ///     ...         resource == ?resource
    ///     ...     );
    ///     ... ''')
    ///     >>> policy_set.add_template(template)
    fn add_template(&mut self, template: &PolicyTemplate) -> PyResult<()> {
        self.templates.insert(
            template.get_template_id().to_string(),
            template.get_template_text().to_string(),
        );
        Ok(())
    }

    /// Add a template-linked policy to the set.
    ///
    /// This method creates a policy from a template by filling in the slot values.
    ///
    /// Args:
    ///     policy_id (str): Unique identifier for the policy
    ///     template_id (str): ID of the template to use
    ///     slots (dict): Dictionary mapping slot names to entity UIDs
    ///
    /// Raises:
    ///     ValueError: If the template doesn't exist or slot values are invalid
    ///
    /// Example:
    ///     >>> policy_set.add_template_linked_policy(
    ///     ...     "alice-view-report",
    ///     ...     "view-template",
    ///     ...     {"principal": 'User::"alice"', "resource": 'Document::"report"'}
    ///     ... )
    fn add_template_linked_policy(
        &mut self,
        policy_id: String,
        template_id: String,
        slots: &Bound<'_, PyDict>,
    ) -> PyResult<()> {
        // Check if template exists
        if !self.templates.contains_key(&template_id) {
            return Err(PyValueError::new_err(format!(
                "Template '{}' not found",
                template_id
            )));
        }

        // Convert PyDict to HashMap and validate entity UIDs
        let mut slot_map = HashMap::new();
        for (key, value) in slots.iter() {
            let key_str: String = key.extract()?;
            let value_str: String = value.extract()?;

            // Validate that the value is a valid entity UID
            EntityUid::from_str(&value_str).map_err(|e| {
                PyValueError::new_err(format!("Invalid entity UID '{}': {}", value_str, e))
            })?;

            slot_map.insert(key_str, value_str);
        }

        // Store the template link
        self.template_links
            .insert(policy_id, (template_id, slot_map));
        Ok(())
    }

    /// Get the number of policies in the set (including template-linked policies).
    ///
    /// Returns:
    ///     int: The number of policies
    fn __len__(&self) -> usize {
        self.policies.len() + self.template_links.len()
    }

    /// String representation of the policy set.
    fn __repr__(&self) -> String {
        format!("PolicySet(policies={})", self.policies.len())
    }

    /// Support for copy.copy() - creates a shallow copy.
    ///
    /// Returns:
    ///     PolicySet: A new PolicySet instance with copied data
    fn __copy__(&self) -> Self {
        PolicySet {
            policies: self.policies.clone(),
            templates: self.templates.clone(),
            template_links: self.template_links.clone(),
            next_auto_id: self.next_auto_id,
        }
    }

    /// Support for copy.deepcopy() - creates a deep copy.
    ///
    /// Args:
    ///     memo (dict): Dictionary for memoization (unused but required by protocol)
    ///
    /// Returns:
    ///     PolicySet: A new PolicySet instance with deeply copied data
    fn __deepcopy__(&self, _memo: &Bound<'_, PyDict>) -> Self {
        // Since all our data is owned (HashMap of Strings), clone is effectively a deep copy
        PolicySet {
            policies: self.policies.clone(),
            templates: self.templates.clone(),
            template_links: self.template_links.clone(),
            next_auto_id: self.next_auto_id,
        }
    }
}

impl PolicySet {
    /// Convert to a Cedar PolicySet (internal use).
    pub(crate) fn get_cedar_policy_set(&self) -> CedarPolicySet {
        let mut combined_text = String::new();
        let mut template_id_map: HashMap<String, String> = HashMap::new();
        let mut auto_id_counter = 0;

        // Build combined text with all policies
        for (_id, policy_text) in &self.policies {
            combined_text.push_str(policy_text);
            combined_text.push_str("\n\n");
            auto_id_counter += 1;
        }

        // Add templates to the combined text
        for (template_id, template_text) in &self.templates {
            combined_text.push_str(template_text);
            combined_text.push_str("\n\n");
            // Track the auto-assigned ID for this template
            let auto_id = format!("policy{}", auto_id_counter);
            template_id_map.insert(template_id.clone(), auto_id);
            auto_id_counter += 1;
        }

        // Parse the combined policy set text
        let mut policy_set = match CedarPolicySet::from_str(&combined_text) {
            Ok(ps) => ps,
            Err(e) => {
                eprintln!("Warning: Failed to parse combined policy set: {}", e);
                return CedarPolicySet::new();
            }
        };

        // Add template-linked policies
        for (policy_id, (template_id, slots)) in &self.template_links {
            // Get the auto-assigned template ID
            let auto_template_id = match template_id_map.get(template_id) {
                Some(id) => id,
                None => {
                    eprintln!(
                        "Warning: Template '{}' not found for policy '{}'",
                        template_id, policy_id
                    );
                    continue;
                }
            };

            let tid = match PolicyId::from_str(auto_template_id) {
                Ok(id) => id,
                Err(e) => {
                    eprintln!("Warning: Invalid template ID '{}': {}", auto_template_id, e);
                    continue;
                }
            };

            // Convert slot map to Cedar format
            let mut cedar_slots = HashMap::new();
            for (slot_name, entity_uid_str) in slots {
                let slot_id = match slot_name.as_str() {
                    "principal" => SlotId::principal(),
                    "resource" => SlotId::resource(),
                    _ => {
                        eprintln!(
                            "Warning: Unknown slot name '{}' in policy '{}'",
                            slot_name, policy_id
                        );
                        continue;
                    }
                };

                if let Ok(entity_uid) = EntityUid::from_str(entity_uid_str) {
                    cedar_slots.insert(slot_id, entity_uid);
                } else {
                    eprintln!(
                        "Warning: Invalid entity UID '{}' in policy '{}'",
                        entity_uid_str, policy_id
                    );
                }
            }

            // Create the linked policy
            let pid = match PolicyId::from_str(policy_id) {
                Ok(id) => id,
                Err(e) => {
                    eprintln!("Warning: Invalid policy ID '{}': {}", policy_id, e);
                    continue;
                }
            };

            policy_set.link(tid, pid, cedar_slots).unwrap_or_else(|e| {
                eprintln!("Warning: Failed to link policy '{}': {}", policy_id, e);
            });
        }

        policy_set
    }
}
