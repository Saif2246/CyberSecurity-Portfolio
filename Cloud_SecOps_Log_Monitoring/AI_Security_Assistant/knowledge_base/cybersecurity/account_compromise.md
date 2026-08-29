# Account Compromise

## Definition

Account compromise means an account may have been accessed or controlled by an unauthorized party. Detection should be based on multiple pieces of evidence rather than a single event.

## Defensive Indicators

Common indicators include:

- Multiple failed authentication attempts
- A successful login following suspicious authentication failures
- Authentication from an unexpected source
- Unusual network activity after authentication
- Unexpected administrative activity
- Suspicious cloud control-plane actions
- Changes to security or access configuration

## Investigation

A defender should correlate:

1. Username
2. Source IP
3. Authentication failures
4. Successful authentication
5. Authentication timestamps
6. Network activity after authentication
7. CloudTrail activity
8. Changes to security controls
9. Related evidence from other telemetry sources

## KiroTrace Relevance

KiroTrace can correlate SSH authentication activity with Firewall and CloudTrail events.

A successful login following failed authentication attempts is an indicator that requires investigation. It does not independently prove that an account was compromised.

## Defensive Response

Recommended actions include:

- Validate whether the login was authorized
- Review authentication history
- Review activity associated with the source IP
- Review cloud activity associated with the identity
- Review security-group and policy changes
- Rotate credentials if unauthorized access is confirmed
- Apply MFA where supported
- Restrict unnecessary remote access
- Preserve relevant evidence for investigation
