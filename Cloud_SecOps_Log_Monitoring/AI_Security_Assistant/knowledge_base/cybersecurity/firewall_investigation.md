# Firewall Investigation

## Definition

Firewall telemetry records network activity that can help defenders identify suspicious connections, unexpected access, and network behavior associated with a security incident.

## Defensive Investigation Fields

Important fields include:

- Event timestamp
- Source IP address
- Destination IP address
- Source port
- Destination port
- Protocol
- Action
- Direction
- Username or identity when available
- Related host or resource

## Security-Relevant Activity

Examples of activity that may require investigation include:

- Unexpected connections from a suspicious source IP
- Repeated connections to sensitive services
- Connections occurring shortly after suspicious authentication
- Unexpected inbound access
- Unexpected outbound communication
- Network activity associated with a newly authenticated account
- Network activity occurring after security-control changes

## Investigation Process

A defender should correlate:

1. Event timestamp
2. Source IP
3. Destination
4. Destination port
5. Protocol
6. Firewall action
7. Username or identity when available
8. Authentication timeline
9. CloudTrail activity
10. Other related security events

## KiroTrace Relevance

KiroTrace uses Firewall telemetry as a second security domain during cross-source correlation.

Firewall activity occurring after suspicious SSH authentication can provide additional evidence about activity following authentication.

The relationship between authentication events and network events should be evaluated using source identity, source IP, timestamps, and the available incident timeline.

Firewall evidence alone does not prove compromise or malicious intent.

## Defensive Response

Recommended actions include:

- Validate whether the network connection was authorized
- Identify the source and destination
- Review the destination service
- Review the timing relative to authentication activity
- Review related SSH events
- Review related CloudTrail activity
- Investigate unexpected network access
- Restrict unauthorized access after appropriate investigation
- Preserve relevant firewall evidence
