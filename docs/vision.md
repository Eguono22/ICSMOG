# ICSMOG Vision

## Product Direction

ICSMOG should evolve into a focused cybersecurity monitoring application for small teams that need understandable detection and response workflows without the complexity of a large enterprise platform.

The current codebase already demonstrates intrusion detection, prevention, and event correlation. The next phase is to turn those capabilities into a usable product surface with persistence, ingestion, and reporting.

## Target User

The primary user is a small-team security or IT operations lead who:

- monitors a modest internal network
- does not have a full-scale SIEM team
- wants clear alerts instead of noisy dashboards
- needs lightweight automation for common response actions

## Core Problem

Small organizations often lack tools that are both:

- powerful enough to surface meaningful security events
- simple enough to understand, tune, and operate

ICSMOG should solve this by providing a focused workflow:

1. ingest events
2. detect suspicious behavior
3. correlate related incidents
4. present clear alerts
5. support limited automated response

## Product Promise

ICSMOG helps small teams identify suspicious activity quickly, understand why it was flagged, and take immediate action without needing a large security engineering function.

## MVP Scope

The first product version should focus on:

- network event ingestion
- authentication event ingestion
- rule-based suspicious activity detection
- SIEM-style event correlation for common scenarios
- alert history with severity levels
- API access for dashboards and integrations

The MVP should not try to include every current domain module as a first-class product surface.

## Non-Goals

For the first product phase, ICSMOG is not trying to be:

- a full enterprise SIEM replacement
- a general observability platform for every department
- an advanced ML-first security analytics system
- a complete SOC automation product

## Success Metric

The first meaningful success metric should be:

**A user can submit realistic security events and receive clear, explainable alerts through a stable API with stored history.**

Supporting metrics:

- a new user can run the system locally in under 10 minutes
- common suspicious scenarios are reproduced with sample data
- alerts have clear severity and explanation fields
- repeated runs preserve historical alerts and events

## User Workflow

The ideal first workflow is:

1. the user starts ICSMOG
2. the user sends network or auth events through an API or file import
3. ICSMOG evaluates events against detection rules
4. correlated incidents are grouped into a meaningful alert stream
5. the user reviews alerts and recent activity in a dashboard or API response
6. the user optionally applies a lightweight response action

## Near-Term Build Priorities

1. separate reusable cybersecurity services from demo-only code
2. add event and alert persistence
3. expose ingestion and dashboard endpoints
4. provide realistic sample event feeds
5. build a simple dashboard for alert review

## Decision Filter

Future work should be prioritized only if it improves one of these outcomes:

- clearer security signal
- easier user onboarding
- more useful alert history
- more trustworthy response behavior

If a change mainly expands breadth without improving the primary cybersecurity workflow, it should wait.
