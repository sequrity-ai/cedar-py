use cedar_policy::{Decision as CedarDecision, Response as CedarResponse};
use pyo3::prelude::*;

/// Authorization decision result.
///
/// This represents the result of an authorization decision, including
/// the decision itself (Allow/Deny) and any diagnostic information.
#[pyclass]
pub struct Decision {
    decision: String,
    diagnostics: Vec<String>,
}

#[pymethods]
impl Decision {
    /// Get the decision as a string ('Allow' or 'Deny').
    #[getter]
    fn decision(&self) -> String {
        self.decision.clone()
    }

    /// Get the list of diagnostic messages.
    #[getter]
    fn diagnostics(&self) -> Vec<String> {
        self.diagnostics.clone()
    }

    /// Check if the decision is 'Allow'.
    ///
    /// Returns:
    ///     bool: True if the decision is 'Allow', False otherwise
    fn is_allowed(&self) -> bool {
        self.decision == "Allow"
    }

    /// String representation of the decision.
    fn __repr__(&self) -> String {
        format!(
            "Decision(decision='{}', diagnostics={:?})",
            self.decision, self.diagnostics
        )
    }

    /// Boolean conversion - True if allowed.
    fn __bool__(&self) -> bool {
        self.is_allowed()
    }
}

impl Decision {
    /// Create a Decision from a Cedar Response (internal use).
    pub(crate) fn from_cedar_response(response: CedarResponse) -> Self {
        let decision = match response.decision() {
            CedarDecision::Allow => "Allow",
            CedarDecision::Deny => "Deny",
        }
        .to_string();

        let mut diagnostics = Vec::new();

        // Add information about errors if any
        for error in response.diagnostics().errors() {
            diagnostics.push(format!("Error: {}", error));
        }

        // Add information about reasons (policies that contributed to the decision)
        for reason in response.diagnostics().reason() {
            diagnostics.push(format!("Reason: {}", reason));
        }

        Decision {
            decision,
            diagnostics,
        }
    }
}
