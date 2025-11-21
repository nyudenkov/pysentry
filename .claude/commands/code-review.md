⏺ 📋 Comprehensive Code Review Template & Methodology

🎯 Overview

This template provides a systematic approach for conducting deep, professional code
reviews that I used for the PySentry analysis. It ensures consistent quality,
thoroughness, and actionable insights.

📝 Pre-Review Setup

1. Initialize Review Tracking

# Create systematic todo list for review phases

TodoWrite: [
"Analyze change scope and statistics",
"Review dependency/build changes",
"Review architectural changes",
"Review core functionality changes",
"Review tests and documentation",
"Security and performance analysis",
"Compile final assessment report"
]

2. Gather Change Statistics

# Get comprehensive change overview

git diff --cached --stat
git diff --cached --name-status
git diff --cached --numstat

# Understand change scope

git log --oneline -10 # Recent commits for context

---

🔍 Systematic Review Process

Phase 1: Scope & Impact Analysis

Goal: Understand the breadth and nature of changes

# Statistical analysis

- Total files changed
- Lines added/removed per file
- New files vs modifications vs deletions
- Change distribution across modules

Assessment Framework:

- Scope: Trivial | Minor | Medium | Major | Architectural
- Risk Level: Low | Medium | High | Critical
- Change Type: Bugfix | Feature | Refactor | Security | Performance

Phase 2: Dependency & Infrastructure Review

Focus: Build system, dependencies, tooling changes

Check List:

- New dependencies: necessity, security, maintenance status
- Version updates: breaking changes, security fixes
- Build configuration: correctness, optimization
- Tool configuration: linting, formatting, CI/CD

Template Assessment:

### Dependency Changes (Cargo.toml/package.json/etc.)

**Impact**: [Low/Medium/High] | **Quality**: [Poor/Good/Excellent]

- New deps: `dep-name = "version"` - [Purpose and justification]
- Removed deps: [Cleanup rationale]
- Version changes: [Breaking change implications]

**Assessment**: [Security concerns, maintenance burden, appropriateness]

Phase 3: Architectural Changes Review

Focus: Major structural changes, new modules, refactoring

Key Areas:

- Module organization and separation of concerns
- New abstractions and their appropriateness
- Interface design and backward compatibility
- Design pattern adherence

Template Assessment:

### [Component Name] (file.rs - **NEW/MODIFIED**)

**Impact**: [Low/Medium/High] | **Quality**: [Poor/Good/Excellent]

- **[X] lines** of [new/modified] functionality
- [Key architectural decisions]
- **Strengths**:
  - [Specific positive aspects]
- **Concerns**:
  - [Specific issues or risks]

Phase 4: Core Functionality Review

Focus: Business logic, algorithms, data handling

Analysis Points:

- Correctness of implementation
- Error handling patterns
- Performance implications
- Edge case handling
- Testing coverage

Phase 5: Security & Performance Analysis

Security Checklist:

- No hardcoded secrets or credentials
- Input validation and sanitization
- Safe handling of user data
- Proper authentication/authorization
- No unsafe code patterns

Performance Checklist:

- Algorithmic complexity assessment
- Memory usage patterns
- I/O efficiency
- Caching strategies
- Resource cleanup

---

📊 Assessment Framework

Quality Ratings

- Poor: Significant issues, needs major revision
- Good: Solid implementation with minor concerns
- Excellent: Exemplary code quality, best practices

Impact Levels

- Low: Isolated changes, minimal risk
- Medium: Moderate scope, some integration risk
- High: Wide-reaching changes, significant impact
- Critical: Core system changes, high risk

Risk Categories

- Architecture: Structural changes, module relationships
- Security: Vulnerability introduction, data exposure
- Performance: Speed, memory, resource usage degradation
- Compatibility: Breaking changes, API modifications
- Maintainability: Code complexity, technical debt

---

📋 Report Structure Template

# [Project] Code Review Report

## Executive Summary

[2-3 sentence overview: scope, quality, recommendation]

**Change Scope**: [Scope level]
**Risk Level**: [Risk level]
**Quality Assessment**: [✅/⚠️/❌] [Overall rating]

---

## 🏗️ Major Changes Analysis

### 1. [Change Category 1]

**Impact**: [Level] | **Quality**: [Rating]
[Detailed analysis with specific line counts, architectural decisions]

### 2. [Change Category 2]

[Continue pattern...]

---

## 🔍 Detailed Quality Analysis

### **Strengths** ✅

1. **[Category]**: [Specific positive aspects]
2. **[Category]**: [More strengths...]

### **Areas of Concern** ⚠️

1. **[Issue Category]**: [Specific concerns and risk level]
2. **[Issue Category]**: [More concerns...]

### **Security Assessment** 🔒

- [Detailed security analysis with checkmarks]

---

## 📊 Impact Assessment Table

| Component | Files | +Lines | -Lines | Risk |
| --------- | ----- | ------ | ------ | ---- |

[Tabular breakdown of changes]

---

## ✅ Recommendations

### **[Approve/Reject/Approve with Conditions]**

1. **[Category]**: [Specific actionable recommendation]
2. **[Category]**: [More recommendations...]

### **Pre-Merge Verification**

- [ ] [Specific test to run]
- [ ] [Integration check]
- [ ] [Performance validation]

---

## 🎯 Conclusion

[Final assessment paragraph with clear verdict]

**Final Verdict**: [✅/⚠️/❌] **[ACTION]** - [Brief justification]

---

🛠️ Tools & Commands Reference

Git Analysis Commands

# Change statistics

git diff --cached --stat
git diff --cached --numstat
git diff --cached --name-status

# Detailed file analysis

git diff --cached [file] | head -50
git diff --cached [file] | tail -50
git show HEAD:[file] # For deleted files

# File structure analysis

rg "^(pub )?fn|^impl|^struct|^enum" [file] # Rust
find . -name "\*.rs" -exec wc -l {} + | sort -n # Line counts

Analysis Patterns

# For each major file:

1. git diff --cached [file] | head -50 # First part
2. git diff --cached [file] | tail -50 # End part
3. Read key sections with context
4. Check for patterns: new APIs, error handling, tests

---

🎓 Best Practices for Review Quality

1. Systematic Approach

- Always use todo tracking to ensure completeness
- Follow the same order: scope → dependencies → architecture → functionality → security
- Don't skip phases even for "small" changes

2. Balanced Analysis

- Look for both strengths and weaknesses
- Consider multiple dimensions: security, performance, maintainability
- Provide specific examples and line references

3. Actionable Feedback

- Give concrete recommendations, not vague concerns
- Suggest specific tests or validations
- Prioritize issues by risk and impact

4. Context Awareness

- Consider project phase (early dev vs production)
- Understand team constraints and deadlines
- Balance perfectionism with pragmatism

5. Clear Communication

- Use consistent terminology and ratings
- Structure for different audiences (technical and management)
- Provide clear verdict with reasoning

---

🔄 Adaptation Guidelines

For Different Project Types

- Libraries: Focus heavily on API design and backward compatibility
- Applications: Emphasize user-facing functionality and performance
- Security Tools: Deep dive into threat model and vulnerability analysis
- DevOps/Infrastructure: Focus on reliability, monitoring, deployment

For Different Change Sizes

- Small Changes: Streamlined template, focus on correctness and style
- Medium Changes: Standard template with emphasis on testing
- Large Changes: Full template with detailed architectural analysis
- Breaking Changes: Extra focus on migration path and compatibility

Team Customization

- Adapt quality criteria to team standards
- Adjust risk tolerance based on project criticality
- Include team-specific tools and processes
- Tailor recommendations to team expertise level

---

This template captures the systematic approach that produced the comprehensive PySentry
review. Use it as a starting framework and adapt based on your specific project needs
and team requirements.
