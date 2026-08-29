# Identity and Access Management (IAM)

## Definition

Identity and Access Management (IAM) is the set of policies, processes, and technologies used to manage digital identities and control access to systems, applications, data, and other resources.

IAM helps ensure that users and services receive only the access they require for authorized activities.

## Core IAM Principles

Important IAM principles include:

- Authentication verifies the identity of a user or service
- Authorization determines what an authenticated identity is allowed to access
- Least privilege limits access to only what is required
- Role-based access control assigns permissions according to defined roles
- Multi-factor authentication adds additional verification factors
- Separation of duties reduces the risk of excessive control by one identity
- Access reviews help identify unnecessary or inappropriate permissions

## IAM Security Indicators

Defenders should investigate IAM-related activity such as:

- Unexpected successful authentication
- Repeated failed authentication followed by successful authentication
- Login from an unusual source IP or location
- Unexpected privilege changes
- New or modified access policies
- Creation of unexpected accounts or credentials
- Use of administrative privileges without an expected business reason
- Suspicious changes to authentication or access-control settings

An individual indicator does not independently prove account compromise.

## Investigation

A defender should correlate:

1. User or service identity
2. Authentication events
3. Source IP or originating system
4. Authentication timestamp
5. Assigned roles or permissions
6. Privilege changes
7. Access-policy changes
8. Related Firewall activity
9. Related SSH activity
10. Related CloudTrail or other cloud control-plane activity

The investigation should establish whether the observed access was authorized and whether the identity performed actions consistent with its expected role.

## KiroTrace Relevance

KiroTrace can use authentication, Firewall, SSH, and CloudTrail telemetry to provide evidence related to identities and access activity.

For example, repeated SSH authentication failures followed by a successful login and subsequent cloud activity may form a correlated security story involving the same source IP or username.

Correlation between IAM-related events and other telemetry increases investigative context but does not independently prove causation or compromise.

## Defensive Response

Recommended defensive actions include:

- Validate whether the authentication or access activity was authorized
- Review the affected identity's recent activity
- Review assigned roles and permissions
- Remove unnecessary privileges according to approved policy
- Enable or enforce MFA where supported
- Review and revoke unauthorized credentials or sessions
- Investigate unexpected privilege or policy changes
- Preserve relevant authentication and audit evidence
- Rotate credentials when compromise is confirmed
- Monitor the identity for further suspicious activity

Actions involving identities, credentials, permissions, or cloud resources should require explicit authorization and appropriate policy controls.
