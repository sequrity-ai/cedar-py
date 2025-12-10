use crate::context_utils::py_dict_to_context;
use crate::schema::CedarSchema;
use cedar_policy::{Context, EntityUid, Request as CedarRequest, Schema};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::str::FromStr;

/// An authorization request.
///
/// This represents a request to authorize whether a principal can perform
/// an action on a resource, optionally with additional context.
#[pyclass]
pub struct Request {
    principal: String,
    action: String,
    resource: String,
    context: Option<Context>, // Store the actual Cedar Context
    schema: Option<Schema>,   // Store the actual Cedar Schema
}

#[pymethods]
impl Request {
    /// Create a new authorization request.
    ///
    /// Args:
    ///     principal (str): The principal entity (e.g., 'User::"alice"')
    ///     action (str): The action entity (e.g., 'Action::"view"')
    ///     resource (str): The resource entity (e.g., 'Document::"report"')
    ///     context (dict, optional): Optional context data as a dictionary
    ///     schema (CedarSchema, optional): Optional schema for request validation
    ///
    /// Example:
    ///     >>> req = Request(
    ///     ...     principal='User::"alice"',
    ///     ...     action='Action::"view"',
    ///     ...     resource='Document::"report"',
    ///     ...     context={"ip_address": "192.168.1.1", "authenticated": True}
    ///     ... )
    #[new]
    #[pyo3(signature = (principal, action, resource, context=None, schema=None))]
    fn new(
        principal: String,
        action: String,
        resource: String,
        context: Option<Bound<'_, PyDict>>,
        schema: Option<&CedarSchema>,
    ) -> PyResult<Self> {
        let cedar_context = if let Some(ctx_dict) = context {
            Some(py_dict_to_context(&ctx_dict)?)
        } else {
            None
        };

        let cedar_schema = schema.map(|s| s.get_schema().clone());

        Ok(Request {
            principal,
            action,
            resource,
            context: cedar_context,
            schema: cedar_schema,
        })
    }

    /// String representation of the request.
    fn __repr__(&self) -> String {
        format!(
            "Request(principal='{}', action='{}', resource='{}')",
            self.principal, self.action, self.resource
        )
    }
}

impl Request {
    /// Convert to a Cedar Request (internal use).
    pub(crate) fn to_cedar_request(&self) -> PyResult<CedarRequest> {
        // Parse the entity UIDs
        let principal = EntityUid::from_str(&self.principal)
            .map_err(|e| PyValueError::new_err(format!("Invalid principal: {}", e)))?;

        let action = EntityUid::from_str(&self.action)
            .map_err(|e| PyValueError::new_err(format!("Invalid action: {}", e)))?;

        let resource = EntityUid::from_str(&self.resource)
            .map_err(|e| PyValueError::new_err(format!("Invalid resource: {}", e)))?;

        // Use the stored context or create an empty one
        let context = self.context.clone().unwrap_or_else(Context::empty);

        // Get schema reference if available
        let schema_ref = self.schema.as_ref();

        // Build the request
        CedarRequest::new(principal, action, resource, context, schema_ref)
            .map_err(|e| PyValueError::new_err(format!("Failed to create request: {}", e)))
    }
}
