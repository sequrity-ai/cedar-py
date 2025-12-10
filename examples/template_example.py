"""
Example demonstrating policy templates in Cedar.

Policy templates allow you to create reusable policy patterns that can be
instantiated with specific values. This is particularly useful for managing
large numbers of similar policies.
"""

from cedar_py import PolicySet, PolicyTemplate, Request, is_authorized


def main():
    print("=== Cedar-py Policy Template Example ===\n")

    # Create a policy set
    policies = PolicySet()

    # Define a template for document access
    # Templates use ?principal and ?resource as placeholders
    print("Creating a policy template...")
    view_template = PolicyTemplate(
        "document-view-template",
        """
        permit(
            principal == ?principal,
            action == Action::"view",
            resource == ?resource
        );
    """,
    )
    print(f"Template ID: {view_template.template_id}")
    print(f"Template text:\n{view_template.template_text}\n")

    # Add the template to the policy set
    policies.add_template(view_template)

    # Create multiple policies from the template by filling in the slots
    print("Creating template-linked policies...\n")

    # Policy 1: Alice can view the quarterly report
    policies.add_template_linked_policy(
        "alice-view-quarterly-report",
        "document-view-template",
        {"principal": 'User::"alice"', "resource": 'Document::"quarterly-report"'},
    )
    print("✓ Created policy: alice-view-quarterly-report")

    # Policy 2: Bob can view the budget spreadsheet
    policies.add_template_linked_policy(
        "bob-view-budget",
        "document-view-template",
        {"principal": 'User::"bob"', "resource": 'Document::"budget-2024"'},
    )
    print("✓ Created policy: bob-view-budget")

    # Policy 3: Charlie can view the presentation
    policies.add_template_linked_policy(
        "charlie-view-presentation",
        "document-view-template",
        {"principal": 'User::"charlie"', "resource": 'Document::"presentation"'},
    )
    print("✓ Created policy: charlie-view-presentation")

    print(f"\nTotal policies in set: {len(policies)}\n")

    # Test authorization scenarios
    print("=" * 60)
    print("Testing Authorization Scenarios")
    print("=" * 60)

    test_cases = [
        {
            "name": "Alice viewing quarterly report",
            "principal": 'User::"alice"',
            "action": 'Action::"view"',
            "resource": 'Document::"quarterly-report"',
            "expected": True,
        },
        {
            "name": "Alice viewing budget (not allowed)",
            "principal": 'User::"alice"',
            "action": 'Action::"view"',
            "resource": 'Document::"budget-2024"',
            "expected": False,
        },
        {
            "name": "Bob viewing budget",
            "principal": 'User::"bob"',
            "action": 'Action::"view"',
            "resource": 'Document::"budget-2024"',
            "expected": True,
        },
        {
            "name": "Bob editing budget (not allowed)",
            "principal": 'User::"bob"',
            "action": 'Action::"edit"',
            "resource": 'Document::"budget-2024"',
            "expected": False,
        },
        {
            "name": "Charlie viewing presentation",
            "principal": 'User::"charlie"',
            "action": 'Action::"view"',
            "resource": 'Document::"presentation"',
            "expected": True,
        },
    ]

    for i, test in enumerate(test_cases, 1):
        print(f"\nTest {i}: {test['name']}")
        print(f"  Principal: {test['principal']}")
        print(f"  Action: {test['action']}")
        print(f"  Resource: {test['resource']}")

        request = Request(
            principal=test["principal"],
            action=test["action"],
            resource=test["resource"],
        )

        decision = is_authorized(request, policies)
        result = "✓ ALLOWED" if decision.is_allowed() else "✗ DENIED"
        expected = "✓ ALLOWED" if test["expected"] else "✗ DENIED"

        print(f"  Decision: {result}")
        print(f"  Expected: {expected}")

        if decision.is_allowed() == test["expected"]:
            print("  Status: ✓ PASS")
        else:
            print("  Status: ✗ FAIL")

    # Demonstrate using multiple templates
    print("\n" + "=" * 60)
    print("Using Multiple Templates")
    print("=" * 60)

    # Create another template for edit permissions
    edit_template = PolicyTemplate(
        "document-edit-template",
        """
        permit(
            principal == ?principal,
            action == Action::"edit",
            resource == ?resource
        );
    """,
    )

    policies.add_template(edit_template)

    # Add edit permissions
    policies.add_template_linked_policy(
        "alice-edit-quarterly-report",
        "document-edit-template",
        {"principal": 'User::"alice"', "resource": 'Document::"quarterly-report"'},
    )

    print("\nAdded edit template and linked policy for Alice")
    print(f"Total policies now: {len(policies)}")

    # Test Alice editing the quarterly report
    print("\nTest: Alice editing quarterly report")
    edit_request = Request(
        principal='User::"alice"',
        action='Action::"edit"',
        resource='Document::"quarterly-report"',
    )

    decision = is_authorized(edit_request, policies)
    print(f"Decision: {'✓ ALLOWED' if decision.is_allowed() else '✗ DENIED'}")

    print("\n" + "=" * 60)
    print("Benefits of Policy Templates:")
    print("=" * 60)
    print("1. Reusability: Define a pattern once, use it many times")
    print("2. Consistency: All policies from a template follow the same structure")
    print("3. Maintainability: Update the template to affect all linked policies")
    print("4. Scalability: Easy to manage large numbers of similar policies")
    print("5. Type Safety: Template slots are validated at link time")


if __name__ == "__main__":
    main()
