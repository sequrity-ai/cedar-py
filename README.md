# Cedar-py

Python bindings for the [Cedar policy language](https://www.cedarpolicy.com/).

Cedar is a language for defining permissions as policies, which describe who should have access to what. It is used for authorization in applications.

## Installation

### From GitHub Releases (Recommended)

Download the appropriate wheel for your platform from the [latest release](https://github.com/sequrity-ai/cedar-py/releases):

```bash
# Linux x86_64
pip install https://github.com/sequrity-ai/cedar-py/releases/download/v0.1.0/cedar_py-0.1.0-cp311-cp311-linux_x86_64.whl

# macOS (Intel)
pip install https://github.com/sequrity-ai/cedar-py/releases/download/v0.1.0/cedar_py-0.1.0-cp311-cp311-macosx_10_12_x86_64.whl

# macOS (Apple Silicon)
pip install https://github.com/sequrity-ai/cedar-py/releases/download/v0.1.0/cedar_py-0.1.0-cp311-cp311-macosx_11_0_arm64.whl

# Windows
pip install https://github.com/sequrity-ai/cedar-py/releases/download/v0.1.0/cedar_py-0.1.0-cp311-cp311-win_amd64.whl
```

### From Source (Requires Rust)

```bash
# Install directly from git
pip install git+https://github.com/sequrity-ai/cedar-py.git

# Or install a specific version/tag
pip install git+https://github.com/sequrity-ai/cedar-py.git@v0.1.0

# Development installation
uv pip install -e .
```

## Quick Start

```python
from cedar_py import PolicySet, Request, is_authorized

# Create a policy set
policies = PolicySet()
policies.add_policy("allow-view", """
    permit(
        principal == User::"alice",
        action == Action::"view",
        resource == Document::"report"
    );
""")

# Make an authorization request
request = Request(
    principal='User::"alice"',
    action='Action::"view"',
    resource='Document::"report"'
)

# Check authorization
decision = is_authorized(request, policies)
print(f"Allowed: {decision.is_allowed()}")  # True
```

## Features

### Core Authorization

- **Policy Management**: Create, add, and validate Cedar policies
- **Authorization Decisions**: Make access control decisions with `is_authorized()`
- **Multiple Policies**: Support for complex policy sets with multiple rules

### Context Support

Pass contextual information with authorization requests:

```python
request = Request(
    principal='User::"alice"',
    action='Action::"view"',
    resource='Document::"report"',
    context={
        "ip_address": "192.168.1.1",
        "timestamp": "2025-12-10T10:00:00Z",
        "authenticated": True
    }
)
```

### Entity Hierarchies

Define entities with attributes and parent relationships:

```python
from cedar_py import EntityStore

# Create entity store
entities = EntityStore()

# Add groups
entities.add_entity('Group::"admins"')
entities.add_entity('Group::"editors"')

# Add users with group membership
entities.add_entity(
    'User::"alice"',
    attrs={"email": "alice@example.com", "role": "admin"},
    parents=['Group::"admins"']
)

# Use hierarchical policies
policies.add_policy("admin-access", """
    permit(
        principal in Group::"admins",
        action == Action::"delete",
        resource
    );
""")

# Alice is allowed because she's in the admins group
decision = is_authorized(request, policies, entities)
```

### Schema Validation

Validate policies against Cedar schemas:

```python
from cedar_py import CedarSchema, validate_policies

# Define schema
schema = CedarSchema("""
    entity User, Group;
    entity Document;

    action view, edit, delete appliesTo {
        principal: [User, Group],
        resource: [Document]
    };
""")

# Validate policies
errors = validate_policies(policies, schema)
if errors:
    for error in errors:
        print(f"Validation issue: {error}")
```

### Type Safety

- Full Python type hints for better IDE support
- Automatic conversion between Python and Cedar types
- Detailed error messages

## Advanced Usage

See [examples/comprehensive_example.py](examples/comprehensive_example.py) for a complete demonstration including:

- Schema definition and validation
- Entity hierarchies with attributes
- Context-aware authorization
- Multiple policy evaluation

## Development

```bash
# Install dependencies
uv sync

# Build the Rust extension
uv run maturin develop

# Run tests (28 tests)
uv run pytest

# Run example
uv run python examples/comprehensive_example.py
```

### Building Wheels

See [docs/BUILDING_WHEELS.md](docs/BUILDING_WHEELS.md) for details on:

- Automated multi-platform builds (Linux, macOS, Windows)
- Local wheel building with maturin
- Publishing to PyPI

## Requirements

- Python 3.8+
- Rust toolchain (for building from source)

Pre-built wheels are available for:

- Linux (x86_64, aarch64)
- macOS (x86_64, Apple Silicon)
- Windows (x86_64)

## Documentation

- [Cedar Policy Language](https://www.cedarpolicy.com/)
- [API Reference](https://docs.cedarpolicy.com/)
- [Learning Guide](docs/LEARNING_SUMMARY.md) - Step-by-step development notes

## License

MIT
