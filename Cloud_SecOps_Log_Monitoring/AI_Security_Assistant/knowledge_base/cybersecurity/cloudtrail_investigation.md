# CloudTrail Investigation

## Definition

AWS CloudTrail records activity performed through AWS accounts, identities, and services. Security investigators can use CloudTrail events to understand who performed an action, what action occurred, when it occurred, and which source was associated with the activity.

## Defensive Investigation Fields

Important fields include:

- Event timestamp
- Event name
- AWS service
- User identity
- Source IP address
- Region
- Resource information
- Request parameters
- Response information
- Authentication or session context

## Security-Relevant Activity

Examples of activity that may require investigation include:

- Changes to security group ingress rules
- Changes to bucket policies
- Unexpected administrative actions
- Creation or modification of identities
- Changes to security controls
- Unexpected activity from an unusual source IP

## Investigation Process

A defender should correlate:

1. Event timestamp
2. Event name
3. User identity
4. Source IP
5. Target resource
6. Request parameters
7. Related authentication activity
8. Related Firewall events
9. Related SSH activity

## KiroTrace Relevance

KiroTrace uses CloudTrail events as one telemetry source during cross-source correlation.

CloudTrail activity occurring after suspicious authentication activity can provide additional evidence about what happened after authentication.

For example, security-group changes or bucket-policy changes occurring after a suspicious login should be investigated in the context of the complete incident timeline.

CloudTrail evidence alone does not prove malicious activity. The event should be evaluated together with identity, timing, source IP, resource, and other available telemetry.

## Defensive Response

Recommended actions include:

- Validate whether the AWS action was authorized
- Identify the identity that performed the action
- Verify the source IP
- Review the affected resource
- Review request parameters
- Compare the event with the authentication timeline
- Review related Firewall and SSH activity
- Preserve relevant CloudTrail evidence
- Revert unauthorized security changes after appropriate investigation
- Review credentials or sessions associated with confirmed unauthorized activity
