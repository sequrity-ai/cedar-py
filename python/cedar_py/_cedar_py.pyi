"""Type stubs for cedar_py._cedar_py module."""

from typing import Optional

class EntityStore:
    """A store for Cedar entities and their relationships."""

    def __init__(self) -> None:
        """Create a new empty entity store."""
        ...

    def add_entity(
        self,
        uid: str,
        attrs: Optional[dict] = None,
        parents: Optional[list[str]] = None,
    ) -> None:
        """Add an entity to the store.

        Args:
            uid: Entity UID (e.g., 'User::"alice"')
            attrs: Optional dictionary of entity attributes
            parents: Optional list of parent entity UIDs
        """
        ...

    def clear(self) -> None:
        """Remove all entities from the store."""
        ...

    def __len__(self) -> int:
        """Get the number of entities."""
        ...

class Decision:
    """Authorization decision result."""

    @property
    def decision(self) -> str:
        """The decision: 'Allow' or 'Deny'."""
        ...

    @property
    def diagnostics(self) -> list[str]:
        """List of diagnostic messages."""
        ...

    def is_allowed(self) -> bool:
        """Returns True if the decision is 'Allow'."""
        ...

class PolicySet:
    """A collection of Cedar policies."""

    def __init__(self) -> None:
        """Create a new empty policy set."""
        ...

    def add_policy(self, policy_id: str, policy_text: str) -> None:
        """Add a policy to the set.

        Args:
            policy_id: Unique identifier for the policy
            policy_text: The Cedar policy text

        Raises:
            ValueError: If the policy is invalid
        """
        ...

    def get_policy(self, policy_id: str) -> Optional[str]:
        """Get a policy by ID.

        Args:
            policy_id: The policy identifier

        Returns:
            The policy text, or None if not found
        """
        ...

class Request:
    """An authorization request."""

    def __init__(
        self,
        principal: str,
        action: str,
        resource: str,
        context: Optional[dict] = None,
        schema: Optional[CedarSchema] = None,
    ) -> None:
        """Create a new authorization request.

        Args:
            principal: The principal entity (e.g., 'User::"alice"')
            action: The action entity (e.g., 'Action::"view"')
            resource: The resource entity (e.g., 'Document::"report"')
            context: Optional context data as a dictionary
            schema: Optional schema for request validation
        """
        ...

class CedarSchema:
    """A Cedar schema for policy validation."""

    def __init__(self, schema_text: str) -> None:
        """Create a schema from Cedar schema text.

        Args:
            schema_text: The schema definition in Cedar schema format

        Raises:
            ValueError: If the schema is invalid
        """
        ...

def is_authorized(
    request: Request,
    policies: PolicySet,
    entities: Optional[EntityStore] = None,
) -> Decision:
    """Make an authorization decision.

    Args:
        request: The authorization request
        policies: The policy set to evaluate
        entities: Optional entity store for hierarchical authorization

    Returns:
        The authorization decision
    """
    ...

def validate_policy(policy_text: str) -> bool:
    """Validate a Cedar policy.

    Args:
        policy_text: The Cedar policy text

    Returns:
        True if valid

    Raises:
        ValueError: If the policy is invalid
    """
    ...

def validate_policies(
    policies: PolicySet,
    schema: CedarSchema,
    mode: str = "strict",
) -> list[str]:
    """Validate policies against a schema.

    Args:
        policies: The policy set to validate
        schema: The schema to validate against
        mode: Validation mode - "strict" or "permissive" (default: "strict")

    Returns:
        A list of validation error/warning messages (empty if valid)
    """
    ...
