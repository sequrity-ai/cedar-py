"""
Example demonstrating copy and deepcopy support for PolicySet.
"""

import copy
from cedar_py import PolicySet

def main():
    print("=== PolicySet Copy Example ===\n")

    # Create original PolicySet
    print("1. Creating original PolicySet...")
    policies = PolicySet.from_str("""
        permit(principal, action, resource);
        forbid(principal == User::"banned", action, resource);
    """)
    print(f"✓ Original has {len(policies)} policies\n")

    # Test shallow copy
    print("2. Creating shallow copy with copy.copy()...")
    policies_copy = copy.copy(policies)
    print(f"✓ Shallow copy has {len(policies_copy)} policies")
    print(f"✓ Original and copy are different objects: {policies is not policies_copy}\n")

    # Test deep copy
    print("3. Creating deep copy with copy.deepcopy()...")
    policies_deepcopy = copy.deepcopy(policies)
    print(f"✓ Deep copy has {len(policies_deepcopy)} policies")
    print(f"✓ Original and deep copy are different objects: {policies is not policies_deepcopy}\n")

    # Modify the copied version
    print("4. Adding policy to shallow copy...")
    policies_copy.add_policy("new-policy", "permit(principal in Group::\"admins\", action, resource);")
    print(f"✓ Original has {len(policies)} policies")
    print(f"✓ Shallow copy has {len(policies_copy)} policies")
    print(f"✓ Deep copy has {len(policies_deepcopy)} policies")
    print("✓ Copies are independent - modifications don't affect original\n")

    # Add more policies to deep copy
    print("5. Adding policies to deep copy using add_policies_from_str()...")
    policy_ids = policies_deepcopy.add_policies_from_str("""
        permit(principal, action == Action::"view", resource);
        permit(principal, action == Action::"edit", resource);
    """)
    print(f"✓ Added {len(policy_ids)} policies (IDs: {policy_ids})")
    print(f"✓ Original has {len(policies)} policies")
    print(f"✓ Shallow copy has {len(policies_copy)} policies")
    print(f"✓ Deep copy has {len(policies_deepcopy)} policies\n")

    print("=== Example Complete ===")
    print("\nSummary:")
    print(f"  - Original PolicySet: {len(policies)} policies")
    print(f"  - Shallow copy: {len(policies_copy)} policies")
    print(f"  - Deep copy: {len(policies_deepcopy)} policies")

if __name__ == "__main__":
    main()
