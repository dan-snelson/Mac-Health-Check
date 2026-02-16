# Project Plan

## Mac Health Check

**Author**: Dan K. Snelson  
**Date**: 2026-01-27  
**Version**: 3.0.0rc4  
**Status**: In Progress

---


## Executive Summary

**One-Sentence Description**: [Mac Health Check](http://snelson.us/mhc) is a user-friendly `zsh` script that surfaces Mac compliance and health information directly to end-users via MDM Self Service portals, using [swiftDialog](https://swiftdialog.app) for interactive feedback.

**Problem Statement**: IT organizations need a practical, automated, and transparent way to communicate device compliance, configuration, and health status to end-users, reducing support tickets and improving security posture.

**Target Audience**: IT administrators, end-users (employees), and support staff in organizations managing Macs with MDM solutions.

**Primary Value Proposition**: Provides actionable, real-time compliance and health information to users and IT, improving device security, user empowerment, and support efficiency.

---


## Project Overview

### Purpose

Mac Health Check exists to bridge the gap between IT compliance requirements and end-user awareness by providing a clear, actionable summary of Mac health and compliance status. It enables organizations to surface critical device information, automate checks, and empower users to self-remediate issues, all within the familiar context of their MDM's Self Service portal.

### Goals

1. Surface real-time Mac compliance and health information to end-users and IT.
2. Support multiple MDM vendors and environments (MDM-agnostic design).
3. Provide actionable, user-friendly feedback and remediation guidance via swiftDialog.
4. Enable easy extensibility for new checks and organizational branding.

### Non-Goals

1. Not a full device management or remediation tool—focuses on reporting and guidance, not enforcement.
2. Does not replace MDM or EDR solutions; complements them.
3. Does not support platforms other than macOS.

### Success Criteria

How will we know this project is successful?

- [ ] End-users can view their Mac's compliance and health status in Self Service.
- [ ] IT can reduce support tickets related to compliance confusion.
- [ ] Script runs reliably across supported macOS versions and MDMs.
- [ ] Users receive clear, actionable remediation steps for common issues.

---


## Use Cases

### Primary Use Cases

#### Use Case 1: End-User Compliance Check
**Actor**: End-user (employee)
**Context**: User opens MDM Self Service and launches Mac Health Check.
**Goal**: Understand current compliance and health status of their Mac.
**Steps:**
1. User launches Mac Health Check from Self Service.
2. Script runs pre-flight checks and gathers system information.
3. swiftDialog displays compliance status, health checks, and remediation guidance.
**Expected Outcome**: User sees a clear summary of their Mac’s status and any required actions.

#### Use Case 2: IT Support Troubleshooting
**Actor**: IT support staff
**Context**: User reports an issue; IT asks user to run Mac Health Check and report results.
**Goal**: Quickly diagnose compliance or configuration issues remotely.
**Steps:**
1. IT instructs user to run Mac Health Check.
2. User shares results or screenshot with IT.
3. IT uses output to guide troubleshooting or remediation.
**Expected Outcome**: IT can efficiently identify and resolve user issues.

### Secondary Use Cases
- Automated compliance reporting for audits
- Testing new health checks in Development mode

### Anti-Use Cases
- Running on non-macOS platforms
- Automated remediation without user awareness

---


## Technical Constraints

### Must Have
- macOS (tested on recent versions, e.g., 12+)
- swiftDialog (minimum version 2.5.6.4805)
- jq (for JSON parsing)
- Root privileges to run system checks
- MDM integration (Addigy, Filewave, Fleet, Kandji, Jamf Pro, JumpCloud, Microsoft Intune, Mosyle, or generic)

### Assumptions
- Users have access to MDM Self Service
- swiftDialog and jq are installed or installable
- Script is run as root (enforced by pre-flight check)
- Network connectivity for some checks (e.g., VPN, webhook)

### Limitations
- Only surfaces information; does not enforce compliance
- Some checks may not be applicable to all organizations
- Requires user interaction for full UI experience
- Not designed for non-macOS systems

### Dependencies
#### External Dependencies
- swiftDialog: User interface
- jq: JSON parsing
- MDM Self Service: Script delivery and launch
#### Internal Dependencies
- Organization-specific branding, support info, and compliance messages

---


## Architecture & Design

### High-Level Architecture

The script is a modular, MDM-agnostic Zsh script that collects system, user, and compliance data, then presents it to the user via swiftDialog. It supports multiple MDMs, organizational branding, and extensible health checks. Logging and webhook integration provide IT with audit and alerting capabilities.

```
┌─────────────┐
│   User      │
└──────┬──────┘
    │
    ▼
┌────────────────────┐
│ Mac-Health-Check   │
│   (Zsh Script)     │
└──────┬──────┬──────┘
    │      │
    │      └─────────────┐
    ▼                    ▼
┌─────────────┐      ┌─────────────┐
│ swiftDialog │      │   Logging   │
└─────────────┘      └─────────────┘
    │
    ▼
┌─────────────┐
│   User UI   │
└─────────────┘
```

### Core Components

#### Component 1: Pre-flight & Environment Checks
**Purpose**: Ensure environment is ready (root, dependencies, logging)
**Responsibilities**:
- Validate root privileges
- Check/install swiftDialog and jq
- Initialize logging
**Key Functions/Methods**:
- `preFlight()` - logs pre-flight steps
- `dialogCheck()` - ensures swiftDialog is present
**Inputs**: System state, environment variables
**Outputs**: Log entries, error/fatal exit if unmet

#### Component 2: Data Collection & Health Checks
**Purpose**: Gather system, user, and compliance data
**Responsibilities**:
- Collect OS, hardware, user, network, VPN, and MDM info
- Run health/compliance checks
**Key Functions/Methods**:
- Variable assignments, modular check functions
**Inputs**: System commands, environment
**Outputs**: Data for UI and logs

#### Component 3: User Interface (swiftDialog)
**Purpose**: Present results and guidance to user
**Responsibilities**:
- Build JSON for swiftDialog
- Display compliance, health, and remediation info
**Key Functions/Methods**:
- `mainDialogJSON`, `dialogUpdate()`
**Inputs**: Collected data, branding
**Outputs**: Interactive dialog window

#### Component 4: Logging & Webhook
**Purpose**: Record actions and optionally alert IT
**Responsibilities**:
- Log to file
- Send webhook to Teams/Slack if configured
**Key Functions/Methods**:
- `updateScriptLog()`, `webHookMessage()`
**Inputs**: Script events, results
**Outputs**: Log entries, webhook messages


### Data Model

#### Key Data Structures

**mainDialogJSON** (swiftDialog UI definition):
```
{
    "title": "string",
    "message": "string",
    "listitems": [
        { "title": "string", "status": "ok|warning|error", "subtitle": "string" },
        ...
    ],
    "progress": int,
    ...
}
```

**Script Variables**:
```
scriptVersion: string
operationMode: string
osVersion, osBuild, serialNumber, computerName, etc.: string
loggedInUser, loggedInUserID, etc.: string
supportTeamName, supportTeamEmail, etc.: string
```

#### Data Flow
1. Data is collected from system commands and environment variables.
2. Data is processed and formatted into JSON for swiftDialog.
3. Results are displayed to the user and logged to file; optionally sent via webhook.

### State Management

- **Configuration State**: Set via script variables and parameters (branding, thresholds, MDM type).
- **Runtime State**: Maintained in memory (variables, JSON objects) during script execution.
- **Persistent State**: Log file at /var/log/org.churchofjesuschrist.log; no persistent user data.

---


## User Interface Design

### User Experience Flow
1. User launches Mac Health Check from Self Service.
2. System performs pre-flight and health checks, displaying progress via swiftDialog.
3. User sees a summary of compliance, health, and remediation steps in an interactive dialog.

### Interface Elements
#### Primary Interface: swiftDialog Window
**Type**: GUI (native macOS dialog via swiftDialog)
**Key Elements**:
- Title, message, and branding (organization logo/banner)
- List of health/compliance checks with status icons (ok, warning, error)
- Progress bar for check execution
- Help button with support contact info
- Remediation instructions in subtitles

**Sample Output/Mockup**:
```
┌─────────────────────────────────────────────┐
│ Mac Health Check                           │
│---------------------------------------------│
│ [✓] FileVault Enabled                      │
│ [!] VPN Not Connected                      │
│ [✗] OS Update Required                     │
│---------------------------------------------│
│ For assistance, contact IT Support...       │
└─────────────────────────────────────────────┘
```

### Error Handling & User Feedback
**Error States**:
- Missing root/jq/swiftDialog → Fatal error, script exits with message
- Invalid JSON for dialog → Error, script exits
- Health check failures → Shown as warning/error in dialog list
**Progress Indicators**:
- Progress bar in swiftDialog reflects check completion
**Help/Documentation Access**:
- Help button in dialog shows support contact info and knowledge base link

---


## Implementation Approach

### Technology Stack
- **Primary Language**: Zsh (macOS shell scripting)
- **Key Libraries/Frameworks**:
    - swiftDialog (user interface)
    - jq (JSON parsing)
- **Build Tools**: None (interpreted script)
- **Testing Framework**: Manual and script-based validation

### File Structure
```
Mac-Health-Check/
├── Mac-Health-Check.zsh         # Main script
├── Resources/
│   └── projectPlan.md           # Project plan (this file)
│   └── [branding, images, etc.]
├── [MDM-specific folders]/       # (if needed)
├── README.md
└── ...
```

### Core Algorithms/Logic
#### Algorithm 1: Pre-flight Checks
**Purpose**: Ensure environment is ready before running checks
**Approach**:
1. Check for root privileges
2. Validate/install swiftDialog and jq
3. Initialize logging
**Edge Cases**:
- Missing dependencies → Fatal error, exit
- Not root → Fatal error, exit

#### Algorithm 2: Health Check Execution
**Purpose**: Gather and report compliance/health status
**Approach**:
1. Collect system/user/MDM info
2. Run modular health checks (disk, OS, VPN, etc.)
3. Build JSON for swiftDialog
4. Display results and remediation
**Edge Cases**:
- Incomplete data → Show warning/error in dialog
- MDM not detected → Use generic checks

### Configuration Strategy
**User-Configurable Settings**:
- `operationMode` - [Default: Self Service] - Controls script mode (Debug, Development, Silent, etc.)
- `organizationBrandingBannerURL` - [Default: sample image] - Branding
- `allowedMinimumFreeDiskPercentage` - [Default: 10] - Disk compliance threshold
- `vpnClientVendor` - [Default: paloalto] - VPN check type
**Configuration Method**: Script parameters, variable overrides, environment variables
**Configuration Validation**: Pre-flight checks and fatal errors for invalid/missing config

---


## Testing Strategy

### Test Modes
- **Development Mode**: Enables testing of individual health checks and verbose output
- **Test Mode**: Runs all checks with test data/parameters
- **Production Mode**: Default; runs in Self Service for end-users

### Test Scenarios
1. **Happy Path**: User runs script, all checks pass, dialog displays green status
2. **Edge Cases**:
    - Missing swiftDialog/jq
    - Not run as root
    - MDM not detected
    - VPN not connected
3. **Error Conditions**:
    - Health check fails (e.g., FileVault off, disk space low)
    - JSON validation fails
4. **Performance**: Script completes in reasonable time (<1 minute typical)

### Validation Checklist
- [ ] Script runs as root
- [ ] swiftDialog and jq present or installed
- [ ] All health checks execute and report status
- [ ] UI displays correctly for all supported MDMs

---


## Error Handling

### Error Categories
1. **User Errors**: Not running as root, launching outside Self Service (fatal, exit with message)
2. **System Errors**: Missing dependencies, failed system commands (fatal or warning, exit or display in dialog)
3. **Configuration Errors**: Invalid or missing config/branding (fatal, exit)
4. **Network Errors**: Webhook or VPN checks fail (warning, shown in dialog)

### Error Response Strategy
**Fatal Errors** (stop execution):
- Not root, missing swiftDialog/jq, invalid JSON → Exit with error message
**Recoverable Errors** (continue with warning):
- Health check fails, network unavailable → Show warning in dialog, log warning
**Silent Failures** (log but continue):
- Non-critical info missing (e.g., optional branding) → Log and continue

### Logging Strategy
**Log Levels**:
- ERROR: Fatal/system errors
- WARNING: Health check or recoverable issues
- NOTICE: Key script events
- INFO: General progress
- DEBUG: Only in Debug mode
**Log Location**: /var/log/org.churchofjesuschrist.log
**Log Format**: Timestamped, prefixed by log level and event

---


## Security Considerations
### Authentication/Authorization
- Script must be run as root (enforced by pre-flight check)
- No user authentication; relies on MDM Self Service for access control
### Sensitive Data Handling
- Does not collect or transmit sensitive user data
- Webhook URLs (if used) are passed as parameters, not stored
### Input Validation
- Validates all required parameters and dependencies at runtime
- Ensures only valid JSON is passed to swiftDialog
### Privilege Requirements
- Requires root privileges for system checks and some commands

---


## Deployment Strategy
### Prerequisites
**System Requirements**:
- OS: macOS 12 or later (tested on recent versions)
- Dependencies: swiftDialog (2.5.6.4805+), jq
- Permissions: root access
**Preparation Steps**:
1. Ensure swiftDialog and jq are installed (script will attempt install if missing)
2. Configure branding and thresholds as needed
3. Deploy script via MDM Self Service
### Installation Process
1. Copy Mac-Health-Check.zsh to deployment location
2. Set executable permissions
3. Add to MDM Self Service catalog
### Configuration Process
1. Set script parameters for branding, thresholds, etc.
2. Test in Development mode
3. Move to Production/Self Service mode
### Verification Process
- [ ] Script runs as root from Self Service
- [ ] swiftDialog UI appears and displays checks
- [ ] Log file is created and updated

---


## Maintenance & Updates
### Version Strategy
- **Version Format**: Semantic versioning (major.minor.patch, e.g., 3.0.0rc4)
- **Version Increments**:
    - Major: Breaking changes or major new features
    - Minor: New checks/features, backward compatible
    - Patch: Bug fixes, minor improvements
### Update Process
- Updates distributed via MDM or repository
- Recommend testing in Development mode before production rollout
### Backward Compatibility
- Strive for compatibility with previous macOS and MDM versions
### Deprecation Policy
- Deprecated features noted in changelog and removed in major releases

---


## Documentation Plan
### User Documentation
- [ ] README with quick start guide
- [ ] Detailed usage instructions
- [ ] Configuration reference
- [ ] Troubleshooting guide
- [ ] FAQ
### Developer Documentation
- [ ] Architecture overview
- [ ] Code comments and inline documentation
- [ ] Contributing guidelines
### Operational Documentation
- [ ] Deployment guide
- [ ] Runbook for common issues
- [ ] Change log

---


## Support & Community
### Support Channels
- **Primary Support**: Organization IT support (contact info in dialog)
- **Community Support**: GitHub Discussions/Issues (if public)
- **Issue Tracking**: GitHub Issues
### Response Expectations
- Response time as per organization or community policy
### Contributing
- Open source; contributions via pull requests and issues

---


## Metrics & Monitoring
### Success Metrics
- Number of successful script runs
- Reduction in compliance-related support tickets
- User satisfaction with clarity of compliance info
### Monitoring Plan
- Monitor log file for errors/warnings
- Use webhook integration for alerting IT of failures
- IT responds to alerts as per support policy

---


## Timeline & Milestones
### Phase 1: Initial Release (Target: 2026-02-15)
- [ ] Complete core script and health checks
- [ ] Test on all supported MDMs
- [ ] Draft user and admin documentation
### Phase 2: Feedback & Enhancement (Target: 2026-03-15)
- [ ] Collect user/IT feedback
- [ ] Add new health checks and UI improvements
- [ ] Expand documentation and troubleshooting
### Phase 3: Production Rollout (Target: 2026-04-01)
- [ ] Finalize branding and config
- [ ] Organization-wide deployment
- [ ] Monitor and support

---


## Known Issues & Future Enhancements
### Known Limitations
1. Requires root and specific dependencies; may not run in all environments
2. Only surfaces issues; does not remediate automatically
3. Some checks may not apply to all organizations
### Future Enhancement Ideas
1. Add more granular health checks (e.g., EDR status, custom org checks)
2. Localized UI for non-English users
3. Integration with additional ITSM/webhook endpoints
### Technical Debt
- Some checks are tightly coupled to current org needs; refactor for greater modularity

---


## Questions & Decisions
### Open Questions
1. Should additional remediation automation be added?
2. What is the best way to support non-English users?
### Key Decisions Made
| Decision | Rationale | Date | Decided By |
|----------|-----------|------|------------|
| Use swiftDialog for UI | Modern, user-friendly, scriptable | 2026-01-21 | Dan K. Snelson |
| MDM-agnostic design | Support multiple orgs | 2026-01-21 | Dan K. Snelson |
### Rejected Alternatives
| Alternative | Why It Was Rejected |
|-------------|---------------------|
| AppleScript dialogs | Not as flexible or modern |
| Hardcoded MDM logic | Limits portability |

---


## References & Resources
### Inspiration
- Inspired by @talkingmoose, @robjschroeder, and community contributions
### Documentation
- https://snelson.us/mhc
- swiftDialog documentation: https://github.com/bartreardon/swiftDialog
### Related Projects
- DDM-OS-Reminder
- App Auto-Patch

---


## Approval & Sign-off
### Review Process
- [ ] Technical review by: IT Engineering
- [ ] Security review by: Security Team
- [ ] Stakeholder approval by: IT Leadership
### Sign-off
**Plan Approved By**: ___________________  
**Date**: ___________________  
**Ready for Implementation**: Yes / No

---

## Implementation Notes

> Once this plan is approved, use this section to track implementation progress and capture any deviations from the plan.

### Implementation Log

- [Date]: [What was implemented]
- [Date]: [Any changes to the plan and why]
- [Date]: [Progress update]

### Lessons Learned

[After implementation, what did you learn that would improve this plan for next time?]

---

**End of Project Plan**

---