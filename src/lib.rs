use cedar_policy::{Authorizer, Policy};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use std::str::FromStr;

mod context_utils;
mod decision;
mod entity_store;
mod policy_set;
mod request;
mod schema;

use decision::Decision;
use entity_store::EntityStore;
use policy_set::PolicySet;
use request::Request;
use schema::CedarSchema;

/// Validate a Cedar policy text.
///
/// Args:
///     policy_text (str): The Cedar policy text to validate
///
/// Returns:
///     bool: True if the policy is valid
///
/// Raises:
///     ValueError: If the policy is invalid with error details
#[pyfunction]
fn validate_policy(policy_text: &str) -> PyResult<bool> {
    match Policy::from_str(policy_text) {
        Ok(_) => Ok(true),
        Err(e) => Err(PyValueError::new_err(format!("Invalid policy: {}", e))),
    }
}

/// Make an authorization decision.
///
/// Args:
///     request (Request): The authorization request
///     policies (PolicySet): The policy set to evaluate against
///     entities (EntityStore, optional): Optional entity store for hierarchical policies
///
/// Returns:
///     Decision: The authorization decision with diagnostics
///
/// Example:
///     >>> store = EntityStore()
///     >>> store.add_entity('User::"alice"', parents=['Group::"admins"'])
///     >>> decision = is_authorized(request, policies, store)
#[pyfunction]
#[pyo3(signature = (request, policies, entities=None))]
fn is_authorized(
    request: &Request,
    policies: &PolicySet,
    entities: Option<&EntityStore>,
) -> PyResult<Decision> {
    // Create the authorizer
    let authorizer = Authorizer::new();

    // Convert our request to a Cedar request
    let cedar_request = request.to_cedar_request()?;

    // Get the Cedar policy set
    let policy_set = policies.get_cedar_policy_set();

    // Get entities or use empty set
    let cedar_entities = if let Some(store) = entities {
        store.to_cedar_entities()?
    } else {
        cedar_policy::Entities::empty()
    };

    // Make the authorization decision
    let response = authorizer.is_authorized(&cedar_request, &policy_set, &cedar_entities);

    Ok(Decision::from_cedar_response(response))
}

/// Python bindings for the Cedar policy language.
#[pymodule]
fn _cedar_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PolicySet>()?;
    m.add_class::<Request>()?;
    m.add_class::<Decision>()?;
    m.add_class::<EntityStore>()?;
    m.add_class::<CedarSchema>()?;
    m.add_function(wrap_pyfunction!(validate_policy, m)?)?;
    m.add_function(wrap_pyfunction!(schema::validate_policies, m)?)?;
    m.add_function(wrap_pyfunction!(is_authorized, m)?)?;
    Ok(())
}
