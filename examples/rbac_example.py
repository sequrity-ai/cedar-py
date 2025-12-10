"""
Example demonstrating role-based access control with Cedar.
"""

from cedar_py import PolicySet, Request, is_authorized


def main():
    print("=== Cedar-py RBAC Example ===\n")

    # Create a policy set
    policies = PolicySet()

    # Policy 1: Admins can do anything
    admin_policy = """
    permit(
        principal in Group::"admins",
        action,
        resource
    );
    """
    policies.add_policy("admin-all-access", admin_policy)

    # Policy 2: Editors can edit documents
    editor_policy = """
    permit(
        principal in Group::"editors",
        action == Action::"edit",
        resource in Folder::"documents"
    );
    """
    policies.add_policy("editors-can-edit-docs", editor_policy)

    # Policy 3: Viewers can view documents
    viewer_policy = """
    permit(
        principal in Group::"viewers",
        action == Action::"view",
        resource in Folder::"documents"
    );
    """
    policies.add_policy("viewers-can-view-docs", viewer_policy)

    print(f"Created policy set with {len(policies)} policies\n")

    # Test cases
    test_cases = [
        {
            "name": "Admin deleting a document",
            "principal": 'User::"admin1"',
            "action": 'Action::"delete"',
            "resource": 'Document::"file1"',
            "expected": 'Would be allowed if admin1 is in Group::"admins"',
        },
        {
            "name": "Editor editing a document",
            "principal": 'User::"editor1"',
            "action": 'Action::"edit"',
            "resource": 'Document::"file1"',
            "expected": 'Would be allowed if editor1 is in Group::"editors" and file1 is in Folder::"documents"',
        },
        {
            "name": "Viewer viewing a document",
            "principal": 'User::"viewer1"',
            "action": 'Action::"view"',
            "resource": 'Document::"file1"',
            "expected": 'Would be allowed if viewer1 is in Group::"viewers" and file1 is in Folder::"documents"',
        },
    ]

    for i, test in enumerate(test_cases, 1):
        print(f"--- Test {i}: {test['name']} ---")
        request = Request(
            principal=test["principal"],
            action=test["action"],
            resource=test["resource"],
        )
        print(f"Request: {request}")

        decision = is_authorized(request, policies)
        print(f"Decision: {decision.decision}")
        print(f"Note: {test['expected']}")
        print()

    print("=== RBAC Example Complete ===")
    print("\nNote: To make these tests pass with 'Allow', you would need to:")
    print("1. Define entities (users, groups, documents, folders)")
    print(
        "2. Establish relationships (user membership in groups, documents in folders)"
    )
    print("3. Pass entities to the is_authorized function")


if __name__ == "__main__":
    main()
