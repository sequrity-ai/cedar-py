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
    """A collection of Cedar policies and templates."""

    def __init__(self) -> None:
        """Create a new empty policy set."""
        ...

    @classmethod
    def from_str(cls, policies_text: str) -> "PolicySet":
        """Create a new PolicySet from Cedar policy text containing multiple policies.

        This is a class method that parses Cedar policy set text and creates
        a new PolicySet instance with all the policies.

        Args:
            policies_text: Cedar policy set text containing one or more policies

        Returns:
            A new PolicySet instance with the parsed policies

        Raises:
            ValueError: If the policies text is invalid

        Example:
            >>> policies = PolicySet.from_str('''
            ...     permit(principal, action, resource);
            ...     forbid(principal == User::"banned", action, resource);
            ... ''')
        """
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

    def add_policies_from_str(self, policies_text: str) -> list[str]:
        """Add multiple policies from a single text string to this PolicySet.

        Parses Cedar policy set text containing multiple policies and adds them all.
        Each policy will be assigned an auto-generated ID like "policy0", "policy1", etc.

        Args:
            policies_text: Cedar policy set text containing one or more policies

        Returns:
            List of auto-generated policy IDs for the added policies

        Raises:
            ValueError: If the policies text is invalid

        Example:
            >>> policies = PolicySet()
            >>> policy_ids = policies.add_policies_from_str('''
            ...     permit(principal, action, resource);
            ...     forbid(principal == User::"banned", action, resource);
            ... ''')
            >>> print(policy_ids)  # ['policy0', 'policy1']
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

    def add_template(self, template: "PolicyTemplate") -> None:
        """Add a policy template to the set.

        Args:
            template: The policy template to add
        """
        ...

    def add_template_linked_policy(
        self, policy_id: str, template_id: str, slots: dict[str, str]
    ) -> None:
        """Add a template-linked policy to the set.

        This creates a policy from a template by filling in the slot values.

        Args:
            policy_id: Unique identifier for the policy
            template_id: ID of the template to use
            slots: Dictionary mapping slot names to entity UIDs

        Raises:
            ValueError: If the template doesn't exist or slot values are invalid
        """
        ...

    def __copy__(self) -> "PolicySet":
        """Support for copy.copy() - creates a shallow copy.

        Returns:
            A new PolicySet instance with copied data
        """
        ...

    def __deepcopy__(self, memo: dict) -> "PolicySet":
        """Support for copy.deepcopy() - creates a deep copy.

        Args:
            memo: Dictionary for memoization

        Returns:
            A new PolicySet instance with deeply copied data
        """
        ...

class PolicyTemplate:
    """A Cedar policy template.

    Policy templates allow you to define reusable policy patterns with slots
    that can be filled in when instantiating the template.
    """

    def __init__(self, template_id: str, template_text: str) -> None:
        """Create a new policy template.

        Args:
            template_id: Unique identifier for the template
            template_text: The Cedar policy template text with slots (e.g., ?principal, ?resource)

        Raises:
            ValueError: If the template text is invalid
        """
        ...

    @property
    def template_id(self) -> str:
        """The template identifier."""
        ...

    @property
    def template_text(self) -> str:
        """The template text with slots."""
        ...

    def instantiate(
        self, policy_id: str, slots: dict[str, str]
    ) -> tuple[str, str, dict[str, str]]:
        """Create a policy from this template by filling in the slots.

        Args:
            policy_id: Unique identifier for the instantiated policy
            slots: Dictionary mapping slot names to entity UIDs

        Returns:
            A tuple of (policy_id, template_id, slots_dict)

        Raises:
            ValueError: If slot values are invalid
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

def validate_template(template_text: str) -> bool:
    """Validate a Cedar policy template.

    Args:
        template_text: The Cedar policy template text

    Returns:
        True if valid

    Raises:
        ValueError: If the template is invalid
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
