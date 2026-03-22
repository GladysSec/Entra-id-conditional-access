# Microsoft Entra ID Conditional Access Lab

**Objective:**  
Configure, test, and validate Conditional Access policies in Microsoft Entra ID to enforce MFA and secure Office 365 resources.

## Scenario & Threat Model
- Target: Test user account
- Goal: Validate MFA enforcement and policy application
- Threat: Unauthorized access / credential compromise43
Threat Mapping: Conditional Access policies prevent unauthorized access and mitigate account compromise risks (aligns with MITRE ATT&CK T1078 – Valid Accounts).

## Tools & Resources
- Microsoft Entra ID / Azure AD
- Office 365 (Exchange Online, Teams)
- Azure Portal (Conditional Access & Sign-in Logs)

Step-by-Step Execution

1. Policy Setup
- Log in to the Microsoft Entra ID portal￼ with your assigned credentials.
- Navigate to Security > Conditional Access > New Policy.
- Name the policy:
Office365-MFA-Lab-Policy
- Assign target users: select the test user and the test group you created.
- Assign target apps: select Office 365.
- Configure access controls: Require MFA
- Enable the policy and save

![Targeted-user](screenshots/kql-Targeted-user.jpg)



