# Unlisted vaults are visible-but-denied, not hidden

We considered hiding vaults that aren't on the allowlist entirely, so the agent couldn't even learn they exist. We decided against it: vault names carry no sensitive content on their own, and the agent needs to see a vault it can't query in order to usefully suggest "add vault X to the allowlist" when it can't find what it's looking for. Vault enumeration returns all vault names; field/item access within a vault still fails closed if that vault isn't on the allowlist.
