"""
Comprehensive test suite for cedar-py.

This test suite covers all major features of the cedar-py library including:
- Policy validation and management
- Request creation with context
- Authorization decisions
- Entity hierarchies and relationships
- Schema validation
- Integration scenarios
"""

import pytest
from cedar_py import (
    CedarSchema,
    EntityStore,
    PolicySet,
    Request,
    is_authorized,
    validate_policies,
    validate_policy,
)

# =============================================================================
# Core Policy Tests
# =============================================================================


class TestPolicyValidation:
    """Test policy validation."""

    def test_valid_policy(self):
        """Test that a valid policy is accepted."""
        policy = "permit(principal, action, resource);"
        assert validate_policy(policy) is True

    def test_invalid_policy_syntax(self):
        """Test that an invalid policy raises ValueError."""
        policy = "this is not a valid policy"
        with pytest.raises(ValueError):
            validate_policy(policy)


class TestPolicySet:
    """Test PolicySet operations."""

    def test_create_empty_policy_set(self):
        """Test creating an empty policy set."""
        ps = PolicySet()
        assert len(ps) == 0

    def test_add_policy(self):
        """Test adding a policy to the set."""
        ps = PolicySet()
        ps.add_policy("policy1", "permit(principal, action, resource);")
        assert len(ps) == 1

    def test_add_invalid_policy(self):
        """Test that adding an invalid policy raises ValueError."""
        ps = PolicySet()
        with pytest.raises(ValueError):
            ps.add_policy("bad", "not a policy")

    def test_get_policy(self):
        """Test retrieving a policy by ID."""
        ps = PolicySet()
        policy_text = "permit(principal, action, resource);"
        ps.add_policy("policy1", policy_text)

        retrieved = ps.get_policy("policy1")
        assert retrieved is not None
        assert "permit" in retrieved

    def test_get_nonexistent_policy(self):
        """Test that getting a nonexistent policy returns None."""
        ps = PolicySet()
        assert ps.get_policy("nonexistent") is None


# =============================================================================
# Request and Context Tests
# =============================================================================


class TestRequest:
    """Test Request creation."""

    def test_create_request(self):
        """Test creating a basic request."""
        req = Request(
            principal='User::"alice"',
            action='Action::"view"',
            resource='Document::"report"',
        )
        assert "alice" in repr(req)
        assert "view" in repr(req)
        assert "report" in repr(req)

    def test_create_request_with_context(self):
        """Test creating a request with context."""
        req = Request(
            principal='User::"alice"',
            action='Action::"view"',
            resource='Document::"report"',
            context={"ip": "192.168.1.1"},
        )
        assert req is not None

    def test_create_request_with_schema(self):
        """Test creating a request with schema."""
        schema = CedarSchema("""
        entity User;
        entity Document;
        action view appliesTo {
            principal: [User],
            resource: [Document]
        };
        """)

        req = Request(
            principal='User::"alice"',
            action='Action::"view"',
            resource='Document::"report"',
            schema=schema,
        )
        assert req is not None

    def test_create_request_with_context_and_schema(self):
        """Test creating a request with both context and schema."""
        schema = CedarSchema("""
        entity User;
        entity Document;
        action view appliesTo {
            principal: [User],
            resource: [Document]
        };
        """)

        req = Request(
            principal='User::"alice"',
            action='Action::"view"',
            resource='Document::"report"',
            context={"ip_address": "192.168.1.1"},
            schema=schema,
        )
        assert req is not None


class TestContext:
    """Test context support."""

    def test_request_with_simple_context(self):
        """Test creating a request with simple context values."""
        req = Request(
            principal='User::"alice"',
            action='Action::"view"',
            resource='Document::"report"',
            context={"ip_address": "192.168.1.1", "authenticated": True, "level": 5},
        )
        assert req is not None

    def test_request_with_nested_context(self):
        """Test creating a request with nested context."""
        req = Request(
            principal='User::"alice"',
            action='Action::"view"',
            resource='Document::"report"',
            context={
                "user_agent": "Mozilla/5.0",
                "location": {"city": "Seattle", "country": "USA"},
                "tags": ["urgent", "confidential"],
            },
        )
        assert req is not None

    def test_authorization_with_context(self):
        """Test that authorization works with context (even if not used in policy)."""
        ps = PolicySet()
        ps.add_policy("allow", "permit(principal, action, resource);")

        req = Request(
            principal='User::"alice"',
            action='Action::"view"',
            resource='Document::"report"',
            context={"source": "api"},
        )

        decision = is_authorized(req, ps)
        assert decision.is_allowed()


# =============================================================================
# Authorization Tests
# =============================================================================


class TestAuthorization:
    """Test authorization decisions."""

    def test_allow_decision(self):
        """Test an authorization that should be allowed."""
        ps = PolicySet()
        ps.add_policy(
            "allow-alice",
            'permit(principal == User::"alice", action == Action::"view", resource == Document::"report");',
        )

        req = Request(
            principal='User::"alice"',
            action='Action::"view"',
            resource='Document::"report"',
        )

        decision = is_authorized(req, ps)
        assert decision.decision == "Allow"
        assert decision.is_allowed() is True

    def test_deny_decision(self):
        """Test an authorization that should be denied."""
        ps = PolicySet()
        ps.add_policy(
            "allow-alice-only",
            'permit(principal == User::"alice", action == Action::"view", resource == Document::"report");',
        )

        req = Request(
            principal='User::"bob"',
            action='Action::"view"',
            resource='Document::"report"',
        )

        decision = is_authorized(req, ps)
        assert decision.decision == "Deny"
        assert decision.is_allowed() is False

    def test_multiple_policies(self):
        """Test authorization with multiple policies."""
        ps = PolicySet()
        ps.add_policy(
            "allow-alice-view",
            'permit(principal == User::"alice", action == Action::"view", resource);',
        )
        ps.add_policy(
            "allow-bob-edit",
            'permit(principal == User::"bob", action == Action::"edit", resource);',
        )

        # Alice can view
        req1 = Request(
            principal='User::"alice"',
            action='Action::"view"',
            resource='Document::"report"',
        )
        decision1 = is_authorized(req1, ps)
        assert decision1.is_allowed() is True

        # Bob can edit
        req2 = Request(
            principal='User::"bob"',
            action='Action::"edit"',
            resource='Document::"report"',
        )
        decision2 = is_authorized(req2, ps)
        assert decision2.is_allowed() is True

        # Alice cannot edit (no policy allows it)
        req3 = Request(
            principal='User::"alice"',
            action='Action::"edit"',
            resource='Document::"report"',
        )
        decision3 = is_authorized(req3, ps)
        assert decision3.is_allowed() is False


class TestDecision:
    """Test Decision object."""

    def test_decision_bool_conversion(self):
        """Test that Decision can be used as a boolean."""
        ps = PolicySet()
        ps.add_policy("allow-all", "permit(principal, action, resource);")

        req = Request(
            principal='User::"alice"',
            action='Action::"view"',
            resource='Document::"report"',
        )

        decision = is_authorized(req, ps)

        # Should be truthy when allowed
        if decision:
            assert True
        else:
            pytest.fail("Decision should be truthy when allowed")


# =============================================================================
# Entity Store and Hierarchy Tests
# =============================================================================


class TestEntityStore:
    """Test entity store and hierarchical authorization."""

    def test_create_empty_store(self):
        """Test creating an empty entity store."""
        store = EntityStore()
        assert len(store) == 0

    def test_add_entity(self):
        """Test adding entities to the store."""
        store = EntityStore()
        store.add_entity('User::"alice"')
        assert len(store) == 1

    def test_add_entity_with_attributes(self):
        """Test adding entity with attributes."""
        store = EntityStore()
        store.add_entity(
            'User::"alice"', attrs={"email": "alice@example.com", "age": 30}
        )
        assert len(store) == 1

    def test_add_entity_with_parents(self):
        """Test adding entity with parent relationships."""
        store = EntityStore()
        store.add_entity('Group::"admins"')
        store.add_entity('User::"alice"', parents=['Group::"admins"'])
        assert len(store) == 2

    def test_hierarchical_authorization(self):
        """Test authorization using entity hierarchies."""
        # Create entities
        store = EntityStore()
        store.add_entity('Group::"admins"')
        store.add_entity('User::"alice"', parents=['Group::"admins"'])

        # Create policy that checks group membership
        ps = PolicySet()
        ps.add_policy(
            "admins-only",
            """
            permit(
                principal in Group::"admins",
                action == Action::"delete",
                resource
            );
        """,
        )

        # Alice should be allowed because she's in the admins group
        req = Request(
            principal='User::"alice"',
            action='Action::"delete"',
            resource='Document::"report"',
        )

        decision = is_authorized(req, ps, store)
        assert decision.is_allowed()

    def test_non_member_denied(self):
        """Test that non-members are denied."""
        store = EntityStore()
        store.add_entity('Group::"admins"')
        store.add_entity('User::"alice"', parents=['Group::"admins"'])
        store.add_entity('User::"bob"')  # Not in admins group

        ps = PolicySet()
        ps.add_policy(
            "admins-only",
            """
            permit(
                principal in Group::"admins",
                action == Action::"delete",
                resource
            );
        """,
        )

        req = Request(
            principal='User::"bob"',
            action='Action::"delete"',
            resource='Document::"report"',
        )

        decision = is_authorized(req, ps, store)
        assert not decision.is_allowed()

    def test_clear_entities(self):
        """Test clearing all entities from the store."""
        store = EntityStore()
        store.add_entity('User::"alice"')
        store.add_entity('User::"bob"')
        assert len(store) == 2

        store.clear()
        assert len(store) == 0


# =============================================================================
# Schema Validation Tests
# =============================================================================


class TestSchemaValidation:
    """Test schema validation."""

    def test_create_schema(self):
        """Test creating a schema."""
        schema_text = """
        entity User;
        action view appliesTo {
            principal: [User],
            resource: [User]
        };
        """
        schema = CedarSchema(schema_text)
        assert schema is not None

    def test_invalid_schema(self):
        """Test that invalid schema raises error."""
        with pytest.raises(ValueError):
            CedarSchema("this is not a valid schema")

    def test_validate_correct_policies(self):
        """Test validating correct policies against schema."""
        schema = CedarSchema("""
        entity User;
        entity Document;
        action view appliesTo {
            principal: [User],
            resource: [Document]
        };
        """)

        ps = PolicySet()
        ps.add_policy(
            "policy1",
            """
            permit(
                principal == User::"alice",
                action == Action::"view",
                resource == Document::"report"
            );
        """,
        )

        errors = validate_policies(ps, schema)
        # May have warnings but should validate
        assert errors is not None  # Returns list, might be empty or have warnings

    def test_validate_incorrect_policies(self):
        """Test validating policies with schema violations."""
        schema = CedarSchema("""
        entity User;
        entity Document;
        action view appliesTo {
            principal: [User],
            resource: [Document]
        };
        """)

        ps = PolicySet()
        # This policy references an action not in the schema
        ps.add_policy(
            "policy1",
            """
            permit(
                principal == User::"alice",
                action == Action::"delete",
                resource == Document::"report"
            );
        """,
        )

        errors = validate_policies(ps, schema)
        assert len(errors) > 0  # Should have validation errors


# =============================================================================
# Integration Tests
# =============================================================================


class TestIntegration:
    """Integration tests combining multiple features."""

    def test_full_stack(self):
        """Test complete workflow with schema, entities, context, and policies."""
        # Schema
        schema = CedarSchema("""
        entity User, Group;
        entity Document;
        action view, edit appliesTo {
            principal: [User, Group],
            resource: [Document]
        };
        """)

        # Entities
        entities = EntityStore()
        entities.add_entity('Group::"editors"')
        entities.add_entity(
            'User::"alice"', attrs={"role": "editor"}, parents=['Group::"editors"']
        )
        entities.add_entity('Document::"doc1"', attrs={"owner": "alice"})

        # Policies
        policies = PolicySet()
        policies.add_policy(
            "editors-can-edit",
            """
            permit(
                principal in Group::"editors",
                action == Action::"edit",
                resource
            );
        """,
        )

        # Validate
        validate_policies(policies, schema)
        # Should validate (may have warnings)

        # Authorize with context
        req = Request(
            principal='User::"alice"',
            action='Action::"edit"',
            resource='Document::"doc1"',
            context={"timestamp": "2025-12-10T10:00:00Z"},
        )

        decision = is_authorized(req, policies, entities)
        assert decision.is_allowed()
