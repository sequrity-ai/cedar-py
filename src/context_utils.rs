use cedar_policy::{Context, RestrictedExpression};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyFloat, PyInt, PyList, PyString};
use serde_json::{json, Value as JsonValue};

/// Convert a Python object to a serde_json Value
pub fn py_to_json(obj: &Bound<'_, PyAny>) -> PyResult<JsonValue> {
    if obj.is_none() {
        Ok(JsonValue::Null)
    } else if let Ok(b) = obj.downcast::<PyBool>() {
        Ok(json!(b.is_true()))
    } else if let Ok(i) = obj.downcast::<PyInt>() {
        let val: i64 = i.extract()?;
        Ok(json!(val))
    } else if let Ok(f) = obj.downcast::<PyFloat>() {
        let val: f64 = f.extract()?;
        Ok(json!(val))
    } else if let Ok(s) = obj.downcast::<PyString>() {
        let val: String = s.extract()?;
        Ok(json!(val))
    } else if let Ok(list) = obj.downcast::<PyList>() {
        let mut vec = Vec::new();
        for item in list.iter() {
            vec.push(py_to_json(&item)?);
        }
        Ok(JsonValue::Array(vec))
    } else if let Ok(dict) = obj.downcast::<PyDict>() {
        let mut map = serde_json::Map::new();
        for (key, value) in dict.iter() {
            let key_str: String = key.extract()?;
            map.insert(key_str, py_to_json(&value)?);
        }
        Ok(JsonValue::Object(map))
    } else {
        Err(PyValueError::new_err(format!(
            "Unsupported type for context: {}",
            obj.get_type().name()?
        )))
    }
}

/// Convert a Python dict to a Cedar Context
pub fn py_dict_to_context(dict: &Bound<'_, PyDict>) -> PyResult<Context> {
    // Convert Python dict to JSON
    let json_value = py_to_json(dict.as_any())?;

    // Convert JSON object to a map of restricted expressions
    if let JsonValue::Object(map) = json_value {
        let mut pairs = Vec::new();

        for (key, value) in map {
            // Convert each JSON value to a RestrictedExpression
            let expr = json_value_to_restricted_expr(&value)?;
            pairs.push((key, expr));
        }

        // Create context from pairs
        Context::from_pairs(pairs)
            .map_err(|e| PyValueError::new_err(format!("Failed to create context: {}", e)))
    } else {
        Err(PyValueError::new_err("Context must be a dictionary"))
    }
}

/// Convert a JSON value to a RestrictedExpression
pub fn json_value_to_restricted_expr(value: &JsonValue) -> PyResult<RestrictedExpression> {
    match value {
        JsonValue::Null => Err(PyValueError::new_err(
            "null values are not supported in context",
        )),
        JsonValue::Bool(b) => Ok(RestrictedExpression::new_bool(*b)),
        JsonValue::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(RestrictedExpression::new_long(i))
            } else {
                Err(PyValueError::new_err(format!(
                    "Number {} is not a valid integer",
                    n
                )))
            }
        }
        JsonValue::String(s) => Ok(RestrictedExpression::new_string(s.clone())),
        JsonValue::Array(arr) => {
            let mut exprs = Vec::new();
            for item in arr {
                exprs.push(json_value_to_restricted_expr(item)?);
            }
            Ok(RestrictedExpression::new_set(exprs))
        }
        JsonValue::Object(map) => {
            let mut pairs = Vec::new();
            for (k, v) in map {
                pairs.push((k.clone(), json_value_to_restricted_expr(v)?));
            }
            Ok(RestrictedExpression::new_record(pairs)
                .map_err(|e| PyValueError::new_err(format!("Invalid record: {}", e)))?)
        }
    }
}
