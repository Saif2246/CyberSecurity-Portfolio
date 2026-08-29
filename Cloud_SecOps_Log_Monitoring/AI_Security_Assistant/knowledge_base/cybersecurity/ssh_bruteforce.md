# SSH Brute Force

## Definition

An SSH brute-force attack is a repeated authentication attempt against an SSH service. The attacker attempts multiple credentials against the same account or service.

## Detection Indicators

Common defensive indicators include:

- Multiple failed SSH authentication attempts
- Repeated attempts from the same source IP
- Repeated attempts against the same username
- A high number of failures within a short time window
- A successful login immediately after repeated failures

## Investigation

A defender should correlate:

1. Source IP
2. Username
3. First failed authentication
4. Last failed authentication
5. Number of failed attempts
6. Successful login timestamp
7. Network activity after successful authentication
8. Cloud control-plane activity associated with the same identity or source

## KiroTrace Relevance

KiroTrace detects repeated SSH failures and can correlate a successful login with subsequent Firewall and CloudTrail activity.

The presence of these indicators does not independently prove compromise. They should be treated as evidence requiring investigation.

## Defensive Response

Recommended defensive actions include:

- Validate whether the successful login was legitimate
- Review authentication logs
- Review activity from the source IP
- Review network activity after authentication
- Review cloud control-plane actions
- Rotate credentials if compromise is confirmed
- Apply MFA where supported
- Restrict SSH exposure
- Use appropriate authentication controls
