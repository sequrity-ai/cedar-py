"""
Comprehensive example demonstrating all Cedar-py features including:
- Context support
- Entity hierarchies
- Schema validation
"""

from cedar_py import (
    CedarSchema,
    EntityStore,
    PolicySet,
    Request,
    is_authorized,
    validate_policies,
)


def main():
    print("=== Cedar-py Comprehensive Example ===\n")

    # 1. Create a schema
    print("1. Creating schema...")
    schema_text = """
    namespace MyApp {
        entity User, Group;
        entity Document {
            owner: User,
        };
        action view appliesTo {
            principal: [User, Group],
            resource: [Document],
            context: {
                ip_address: String,
                time: String,
            }
        };
        action edit appliesTo {
            principal: [User],
            resource: [Document]
        };
    }
    """

    schema = CedarSchema(schema_text)
    print("✓ Schema created\n")

    # 2. Create entity store with relationships
    print("2. Creating entity store with hierarchies...")
    entities = EntityStore()

    # Add groups
    entities.add_entity('MyApp::Group::"admins"')
    entities.add_entity('MyApp::Group::"editors"')

    # Add users with group membership
    entities.add_entity(
        'MyApp::User::"alice"',
        attrs={"email": "alice@example.com", "role": "admin"},
        parents=['MyApp::Group::"admins"'],
    )
    entities.add_entity(
        'MyApp::User::"bob"',
        attrs={"email": "bob@example.com", "role": "editor"},
        parents=['MyApp::Group::"editors"'],
    )
    entities.add_entity(
        'MyApp::User::"charlie"',
        attrs={"email": "charlie@example.com", "role": "viewer"},
    )

    # Add documents
    entities.add_entity(
        'MyApp::Document::"report.pdf"',
        attrs={"owner": "alice", "created": "2025-01-01"},
    )

    print(f"✓ Created {len(entities)} entities\n")

    # 3. Create policies using multiple methods
    print("3. Creating policies...")

    # Method 1: Create PolicySet with multiple policies using from_str
    policies = PolicySet.from_str("""
        permit(
            principal in MyApp::Group::"admins",
            action,
            resource
        );

        permit(
            principal in MyApp::Group::"editors",
            action == MyApp::Action::"edit",
            resource
        );
    """)
    print(f"✓ Created PolicySet with {len(policies)} policies using from_str()\n")

    # Method 2: Add more policies using add_policies_from_str
    print("3b. Adding more policies using add_policies_from_str()...")
    policy_ids = policies.add_policies_from_str("""
        permit(
            principal,
            action == MyApp::Action::"view",
            resource
        );
    """)
    print(f"✓ Added {len(policy_ids)} more policies (IDs: {policy_ids})")
    print(f"✓ PolicySet now has {len(policies)} total policies\n")

    # 4. Validate policies against schema
    print("4. Validating policies against schema...")
    validation_errors = validate_policies(policies, schema)
    if validation_errors:
        print("  Validation issues:")
        for error in validation_errors:
            print(f"  - {error}")
    else:
        print("✓ All policies are valid!\n")

    # 5. Make authorization decisions with context and schema
    print("5. Testing authorization decisions...\n")

    test_cases = [
        {
            "name": "Alice (admin) viewing document (with schema validation)",
            "request": Request(
                principal='MyApp::User::"alice"',
                action='MyApp::Action::"view"',
                resource='MyApp::Document::"report.pdf"',
                context={"ip_address": "192.168.1.1", "time": "2025-12-10T10:00:00Z"},
                schema=schema,
            ),
            "expected": "Allow",
        },
        {
            "name": "Bob (editor) editing document (with schema)",
            "request": Request(
                principal='MyApp::User::"bob"',
                action='MyApp::Action::"edit"',
                resource='MyApp::Document::"report.pdf"',
                schema=schema,
            ),
            "expected": "Allow",
        },
        {
            "name": "Charlie (viewer) viewing document",
            "request": Request(
                principal='MyApp::User::"charlie"',
                action='MyApp::Action::"view"',
                resource='MyApp::Document::"report.pdf"',
            ),
            "expected": "Allow",
        },
        {
            "name": "Charlie (viewer) editing document",
            "request": Request(
                principal='MyApp::User::"charlie"',
                action='MyApp::Action::"edit"',
                resource='MyApp::Document::"report.pdf"',
            ),
            "expected": "Deny",
        },
    ]

    # 6. Demonstrate request validation with schema
    print("\\n6. Testing schema validation during authorization...")
    # Create a request with an action not defined in the schema
    invalid_action_request = Request(
        principal='MyApp::User::"alice"',
        action='MyApp::Action::"delete"',  # Action not defined in schema
        resource='MyApp::Document::"report.pdf"',
        schema=schema,
    )
    try:
        # The validation happens during authorization
        decision = is_authorized(invalid_action_request, policies, entities)
        print(f"  Decision: {decision.decision} (using undefined action)\\n")
    except ValueError as e:
        print(f"  ✓ Schema validation caught error: {e}\\n")

    print("\n7. Running authorization tests...\n")
    test_cases_section = test_cases
    test_cases = []  # Reset for the loop below

    for i, test in enumerate(test_cases_section, 1):
        print(f"Test {i}: {test['name']}")
        decision = is_authorized(test["request"], policies, entities)
        status = "✓" if decision.decision == test["expected"] else "✗"
        print(
            f"  {status} Decision: {decision.decision} (expected: {test['expected']})"
        )
        if decision.diagnostics:
            for diag in decision.diagnostics:
                print(f"    - {diag}")
        print()

    print("=== Example Complete ===")


if __name__ == "__main__":
    main()
