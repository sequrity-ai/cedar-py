"""
Example demonstrating basic Cedar policy usage.
"""

from cedar_py import PolicySet, Request, is_authorized


def main():
    print("=== Cedar-py Basic Example ===\n")

    # Create a policy set
    policies = PolicySet()

    # Add a simple policy
    policy_text = """
    permit(
        principal == User::"alice",
        action == Action::"view",
        resource == Document::"report"
    );
    """

    print("Adding policy:")
    print(policy_text)
    policies.add_policy("allow-alice-view-report", policy_text)

    # Test case 1: Alice viewing report (should be allowed)
    print("\n--- Test 1: Alice viewing report ---")
    request1 = Request(
        principal='User::"alice"',
        action='Action::"view"',
        resource='Document::"report"',
    )
    print(f"Request: {request1}")

    decision1 = is_authorized(request1, policies)
    print(f"Decision: {decision1.decision}")
    print(f"Allowed: {decision1.is_allowed()}")
    if decision1.diagnostics:
        print(f"Diagnostics: {decision1.diagnostics}")

    # Test case 2: Bob viewing report (should be denied)
    print("\n--- Test 2: Bob viewing report ---")
    request2 = Request(
        principal='User::"bob"', action='Action::"view"', resource='Document::"report"'
    )
    print(f"Request: {request2}")

    decision2 = is_authorized(request2, policies)
    print(f"Decision: {decision2.decision}")
    print(f"Allowed: {decision2.is_allowed()}")
    if decision2.diagnostics:
        print(f"Diagnostics: {decision2.diagnostics}")

    # Test case 3: Alice editing report (should be denied)
    print("\n--- Test 3: Alice editing report ---")
    request3 = Request(
        principal='User::"alice"',
        action='Action::"edit"',
        resource='Document::"report"',
    )
    print(f"Request: {request3}")

    decision3 = is_authorized(request3, policies)
    print(f"Decision: {decision3.decision}")
    print(f"Allowed: {decision3.is_allowed()}")
    if decision3.diagnostics:
        print(f"Diagnostics: {decision3.diagnostics}")

    print("\n=== Example Complete ===")


if __name__ == "__main__":
    main()
