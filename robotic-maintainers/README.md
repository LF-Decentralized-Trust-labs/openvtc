# Robotic Maintainers for OpenVTC

This is a dummy OpenVTC loopback that when you connect to them will automatically
accept a relationship and issue Verified Relationship credentials back to you

## Environment setup

You will need to create a TDK environment containing the maintainers identities
and secrets.

## Relationship connections

For simplicity, only P-DID to P-DID relationships will be accepted. R-DID requests
will be rejected.

This is mainly to save on keeping any form of state management on the robotic-maintainers
side.
