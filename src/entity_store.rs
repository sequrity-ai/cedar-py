use cedar_policy::{Entities, Entity, EntityUid};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::collections::HashMap;
use std::str::FromStr;
use crate::context_utils::py_to_json;

/// An entity store for Cedar authorization.
///
/// This class manages entities and their relationships, which are used
/// during authorization to evaluate hierarchical policies.
#[pyclass]
pub struct EntityStore {
    entities: HashMap<String, Entity>,
}

#[pymethods]
impl EntityStore {
    /// Create a new empty entity store.
    #[new]
    fn new() -> Self {
        EntityStore {
            entities: HashMap::new(),
        }
    }

    /// Add an entity to the store.
    ///
    /// Args:
        ///     uid (str): The entity UID (e.g., 'User::"alice"')
    ///     attrs (dict, optional): Entity attributes as a dictionary
    ///     parents (list, optional): List of parent entity UIDs (for hierarchies)
    ///
    /// Example:
    ///     >>> store = EntityStore()
    ///     >>> store.add_entity(
    ///     ...     'User::"alice"',
    ///     ...     attrs={"email": "alice@example.com", "role": "admin"},
    ///     ...     parents=['Group::"admins"']
    ///     ... )
    #[pyo3(signature = (uid, attrs=None, parents=None))]
    fn add_entity(
        &mut self,
        uid: String,
        attrs: Option<Bound<'_, PyDict>>,
        parents: Option<Bound<'_, PyList>>,
    ) -> PyResult<()> {
        // Parse the entity UID
        let entity_uid = EntityUid::from_str(&uid)
            .map_err(|e| PyValueError::new_err(format!("Invalid entity UID '{}': {}", uid, e)))?;

        // Parse parent UIDs
        let mut parent_uids = vec![];
        if let Some(parents_list) = parents {
            for parent in parents_list.iter() {
                let parent_str: String = parent.extract()?;
                let parent_uid = EntityUid::from_str(&parent_str)
                    .map_err(|e| PyValueError::new_err(format!("Invalid parent UID '{}': {}", parent_str, e)))?;
                parent_uids.push(parent_uid);
            }
        }

        // Convert attributes to HashMap<String, RestrictedExpression>
        let mut attr_map = HashMap::new();
        if let Some(attrs_dict) = attrs {
            for (key, value) in attrs_dict.iter() {
                let key_str: String = key.extract()?;
                let json_val = py_to_json(&value)?;
                let expr = super::context_utils::json_value_to_restricted_expr(&json_val)?;
                attr_map.insert(key_str, expr);
            }
        }

        // Create the entity using builder pattern
        let entity = Entity::new(
            entity_uid.clone(),
            attr_map,
            parent_uids.into_iter().collect(),
        ).map_err(|e| PyValueError::new_err(format!("Failed to create entity: {}", e)))?;

        self.entities.insert(uid, entity);
        Ok(())
    }

    /// Get the number of entities in the store.
    fn __len__(&self) -> usize {
        self.entities.len()
    }

    /// String representation of the entity store.
    fn __repr__(&self) -> String {
        format!("EntityStore(entities={})", self.entities.len())
    }

    /// Clear all entities from the store.
    fn clear(&mut self) {
        self.entities.clear();
    }
}

impl EntityStore {
    /// Convert to Cedar Entities (internal use).
    pub(crate) fn to_cedar_entities(&self) -> PyResult<Entities> {
        let entities_vec: Vec<Entity> = self.entities.values().cloned().collect();
        Entities::from_entities(entities_vec, None)
            .map_err(|e| PyValueError::new_err(format!("Failed to create entity collection: {}", e)))
    }
}
