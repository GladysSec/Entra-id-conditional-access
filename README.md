## Overview
This lab demonstrates how Conditional Access policies in Microsoft Entra ID can be used to enforce MFA and how authentication attacks can be detected using Microsoft Sentinel and Microsoft Defender XDR.

## Objectives
- Enforce MFA using Conditional Access
- Simulate authentication attacks
- Analyze Entra ID sign-in logs
- Detect MFA fatigue using KQL
- Generate and investigate incidents

## Architecture

Describe flow:
User → Entra ID → Conditional Access → Logs → Sentinel → Incident → Defender XDR

## Lab Setup
- Test users
- Security group
- Break-glass account (excluded)

## Conditional Access Policy

A policy was created to enforce MFA for a controlled user group accessing Office 365, while excluding a break-glass account to prevent administrative lockout.

![Include/Exclude-users](screenshots/Include/Exclude-users.jpg)
![Grant-controls](screenshots/Grant-control.jpg)
