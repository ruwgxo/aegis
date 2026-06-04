# Contributing to Aegis Implementation Guide

Thank you for your interest in contributing to the Aegis Implementation Guide! This document provides guidelines and standards for contributions.

---

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [How to Contribute](#how-to-contribute)
3. [Documentation Standards](#documentation-standards)
4. [YAML Structure Guidelines](#yaml-structure-guidelines)
5. [Content Guidelines](#content-guidelines)
6. [Review Process](#review-process)
7. [Security Disclosures](#security-disclosures)

---

## Code of Conduct

### Our Standards

- **Respectful**: Treat all contributors with respect
- **Constructive**: Provide constructive feedback
- **Collaborative**: Work together toward improvement
- **Professional**: Maintain professional discourse

### Unacceptable Behavior

- Harassment, discrimination, or personal attacks
- Trolling or deliberately inflammatory comments
- Publishing private information
- Other conduct inappropriate in a professional setting

---

## How to Contribute

### Types of Contributions

**Welcome Contributions:**
- Error corrections (typos, formatting, technical errors)
- Clarifications (making complex topics clearer)
- Additional examples (real-world scenarios)
- Performance data (benchmarks, measurements)
- Anti-patterns (common mistakes with solutions)
- Cross-references (improving navigation)

**Require Discussion First:**
- Structural changes (reorganizing chapters/sections)
- New chapters or major sections
- Changes to design principles
- Alternative approaches or architectures

### Contribution Process

1. **Check existing issues**: Ensure not already reported/addressed
2. **Open an issue**: Describe proposed change with rationale
3. **Wait for feedback**: Maintainers will review and provide guidance
4. **Create pull request**: After agreement on approach
5. **Address review comments**: Iterate based on feedback
6. **Merge**: Approved PRs merged by maintainers

---

## Documentation Standards

### File Naming

**Pattern:** `section_[part]_[chapter]_[number]_[shortname].yaml`

**Examples:**
- `section_1_01_introduction.yaml`
- `section_4_03_hybrid_kdf.yaml`
- `chapter_5_index.yaml`

**Rules:**
- All lowercase
- Underscores for separation
- Numbers zero-padded (01, 02, not 1, 2)
- Short names descriptive but concise (<20 chars)

### Version Control

**Commit Messages:**
```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New content or section
- `fix`: Error correction
- `docs`: Documentation meta-changes
- `style`: Formatting, no content change
- `refactor`: Restructuring content
- `test`: Adding tests or examples
- `chore`: Maintenance tasks

**Examples:**
```
fix(section_1_03): Correct cost calculation for High Security profile

High Security profile monthly cost was listed as $7,100 but should be 
$7,150 based on detailed breakdown in the performance section.

Fixes #42
```

```
feat(section_4_05): Add AES-NI optimization example

Added complete code example showing how to enable and verify AES-NI 
hardware acceleration, including runtime detection and fallback logic.
```

---

## YAML Structure Guidelines

### Required Metadata

Every section file must include:

```yaml
document_info:
  chapter: "1"                    # Chapter number
  section: "01"                   # Section number (zero-padded)
  title: "Section Title"          # Clear, descriptive title
  version: "1.0.0"                # Semantic versioning
  author: "Raghav Dinesh"         # Original author
  created: "2025-01-27"           # Creation date (YYYY-MM-DD)
  estimated_pages: 6              # Rough page count
  tags: ["tag1", "tag2"]          # Categorization tags
```

### Standard Section Structure

```yaml
section_content:
  
  # --------------------------------------------------------------------------
  # Overview and Context
  # --------------------------------------------------------------------------
  
  overview: |
    2-4 paragraphs introducing the section
    - What problem does this solve?
    - Why is it important?
    - What will be covered?
  
  # --------------------------------------------------------------------------
  # Core Concepts
  # --------------------------------------------------------------------------
  
  core_concepts:
    
    concept_1:
      definition: |
        Clear definition of the concept
      
      key_components:
        component_1: "Description"
        component_2: "Description"
      
      how_it_works: |
        Step-by-step explanation
      
      real_world_example: |
        Concrete example with actual numbers
      
      related_concepts:
        - "Concept A: How it relates"
        - "Concept B: How it relates"
    
    concept_2:
      # Same structure...
  
  # --------------------------------------------------------------------------
  # Practical Implementation (optional)
  # --------------------------------------------------------------------------
  
  practical_implementation:
    
    task_name:
      overview: "What this accomplishes"
      when_to_use: "Scenarios where applicable"
      prerequisites: "What's needed first"
      
      step_by_step_process:
        step_1:
          action: "What to do"
          details: "How to do it"
          example: "Code or concrete example"
        
        step_2:
          # Continue...
      
      complete_example: |
        Full working example
  
  # --------------------------------------------------------------------------
  # Common Mistakes and Anti-Patterns
  # --------------------------------------------------------------------------
  
  common_mistakes:
    
    mistake_1:
      name: "Descriptive name of mistake"
      
      what_it_looks_like:
        - "Observable symptom 1"
        - "Observable symptom 2"
      
      why_people_do_this: |
        Psychology or reasoning behind mistake
      
      consequences:
        immediate: "Short-term impact"
        long_term: "Long-term impact"
        real_cost: "Quantified cost if possible"
      
      how_to_avoid: |
        Preventive measures
      
      how_to_fix_if_already_stuck: |
        Remediation steps
      
      real_world_example: |
        Actual scenario where this happened
    
    mistake_2:
      # Same structure...
  
  # --------------------------------------------------------------------------
  # Key Takeaways
  # --------------------------------------------------------------------------
  
  key_takeaways:
    
    critical_concepts:
      - "Core concept 1 with key numbers/facts"
      - "Core concept 2 with key numbers/facts"
      - "Core concept 3 with key numbers/facts"
    
    actionable_steps:
      - "Specific action 1 you can take"
      - "Specific action 2 you can take"
      - "Specific action 3 you can take"
    
    common_pitfalls_summary:
      - "Mistake 1 to avoid with core reason"
      - "Mistake 2 to avoid with core reason"
    
    remember_this:
      - "Rule of thumb for quick decisions"
      - "Key tradeoff to understand"
      - "Success metric to track"
    
    next_steps:
      - "Read Section X for..."
      - "Do Y to prepare for..."
```

---

## Content Guidelines

### Writing Style

**Clarity:**
- Use clear, direct language
- Define technical terms on first use
- Avoid jargon where possible
- When jargon necessary, explain it

**Conciseness:**
- One idea per paragraph
- Short sentences (15-20 words average)
- Break long explanations into steps
- Use examples to clarify, not repeat

**Consistency:**
- Use same terminology throughout
- Maintain consistent voice (technical but accessible)
- Follow established patterns in existing sections
- Reference existing definitions rather than redefine

### Technical Accuracy

**Requirements:**
- Cite sources for external claims
- Provide references for algorithms
- Include actual measurements, not estimates
- Specify assumptions clearly

**Verification:**
- Code examples must be syntactically correct
- Performance numbers must be reproducible
- Algorithm descriptions must match specs
- Math must be verifiable

### Examples

**Good Examples:**
- Use realistic scenarios (not "Company X")
- Include actual numbers (not "many" or "some")
- Show complete context (inputs, outputs, errors)
- Explain why example matters

**Structure:**
```yaml
real_world_example: |
  Scenario: [Concrete situation]
  
  Context:
  - [Relevant detail 1]
  - [Relevant detail 2]
  
  [What happened]:
  - [Step 1 with actual data]
  - [Step 2 with actual data]
  
  Results:
  - [Outcome 1 with numbers]
  - [Outcome 2 with numbers]
  
  Lesson: [Key takeaway]
```

### Anti-Patterns

**Structure:**
```yaml
mistake_name:
  name: "Choosing X without considering Y"
  
  what_it_looks_like:
    - "Observable behavior 1"
    - "Observable behavior 2"
  
  why_people_do_this: |
    [Psychological or practical reason]
  
  consequences:
    immediate: "[Short-term cost]"
    long_term: "[Long-term cost]"
    real_cost: "[Quantified impact with example]"
  
  how_to_avoid: |
    [Preventive measures with specific steps]
  
  how_to_fix_if_already_stuck: |
    [Remediation steps with timeline]
  
  real_world_example: |
    [Actual scenario where this occurred]
```

### Performance Data

**Include:**
- Hardware specifications
- Workload characteristics
- Measurement methodology
- Statistical measures (mean, p50, p95, p99)

**Format:**
```yaml
performance_example: |
  Environment:
  - Hardware: AWS m5.2xlarge (8 vCPU, 32GB RAM)
  - Workload: 500 concurrent users, mixed read/write
  - Duration: 1 hour sustained load
  
  Baseline (Classical TLS):
  - Throughput: 5,000 req/sec
  - Latency: p50=15ms, p95=45ms, p99=75ms
  - CPU: 55% average
  
  Aegis Standard:
  - Throughput: 4,800 req/sec (-4%)
  - Latency: p50=16ms (+1ms), p95=47ms (+2ms), p99=79ms (+4ms)
  - CPU: 58% average (+3%)
  
  Analysis: [Interpretation and conclusions]
```

---

## Review Process

### Review Checklist

**Content Review:**
- [ ] Technically accurate
- [ ] Clear and understandable
- [ ] Follows established patterns
- [ ] Examples are complete and correct
- [ ] No contradictions with existing content

**Style Review:**
- [ ] YAML syntax valid
- [ ] Formatting consistent
- [ ] Naming conventions followed
- [ ] Comments appropriate
- [ ] Links and references work

**Completeness:**
- [ ] All required sections present
- [ ] Key takeaways capture main points
- [ ] Anti-patterns include all required fields
- [ ] Examples have sufficient detail

### Review Timeline

- **Simple fixes** (typos, formatting): 1-2 days
- **Content additions** (examples, clarifications): 3-5 days
- **Structural changes**: 1-2 weeks with discussion
- **New chapters**: 2-4 weeks with multiple reviews

### Reviewer Responsibilities

**Reviewers must:**
- Provide specific, actionable feedback
- Explain reasoning for requested changes
- Be timely in reviews (within stated timeline)
- Approve when standards met

**Reviewers should NOT:**
- Nitpick style preferences
- Request changes beyond scope
- Block without clear rationale
- Provide vague feedback

---

## Security Disclosures

### Reporting Security Issues

**DO NOT** open public issues for security vulnerabilities.

Instead:
1. Email: security@[domain].com (replace with actual)
2. Use subject: "Aegis Security: [brief description]"
3. Include:
   - Description of vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if known)

### Security Issue Handling

**Timeline:**
- Initial response: 48 hours
- Triage and assessment: 7 days
- Fix development: 30 days
- Coordinated disclosure: After fix available

**Credit:**
- Reporters credited in release notes (if desired)
- Hall of fame for security contributions
- Responsible disclosure appreciated

---

## Quality Standards

### Code Examples

**Must:**
- Compile/execute without errors
- Include necessary imports/dependencies
- Show error handling
- Be self-contained where possible

**Should:**
- Follow language idioms
- Include comments explaining non-obvious parts
- Use realistic variable names
- Show both success and failure cases

### Mathematical Content

**Notation:**
- Use LaTeX for complex math (will be rendered)
- Explain notation on first use
- Provide intuitive explanations alongside formal
- Include worked examples

**Example:**
```yaml
security_analysis: |
  Key security level: 256 bits (Kyber-1024)
  
  Grover's algorithm reduces this to 128 bits effective against quantum 
  computers. This means a quantum computer would need 2^128 operations 
  to break Kyber-1024, which remains computationally infeasible.
  
  For comparison:
  - Classical security: 2^256 operations (impossible)
  - Quantum security: 2^128 operations (still impossible)
  - Practical threshold: 2^80 operations (barely feasible with nation-state resources)
```

### Diagrams and Visualizations

**Preferred formats:**
- ASCII art for simple flows
- Mermaid diagrams (can be rendered)
- SVG for complex diagrams
- PNG as last resort (harder to edit)

**Requirements:**
- Label all elements clearly
- Use consistent symbols/notation
- Include legend if needed
- Keep simple and focused

---

## Getting Help

### Communication Channels

- **Issues**: Technical questions, bug reports
- **Discussions**: General questions, ideas
- **Pull Requests**: Specific changes with discussion

### Response Times

- **Critical issues** (security, major errors): 24 hours
- **Regular issues** (minor errors, questions): 3-5 days
- **Enhancement requests**: 1-2 weeks

### Maintainer Availability

Maintainers review contributions on a best-effort basis. Please be patient and respectful of their time.

---

## Recognition

### Contributor Credits

All contributors are credited in:
- Release notes
- Contributors list
- Relevant section acknowledgments

### Types of Credit

- **Major contributions**: New chapters, significant sections
- **Substantial improvements**: Large corrections, multiple examples
- **Minor contributions**: Typo fixes, small clarifications

---

## License

By contributing, you agree that your contributions will be licensed under the MIT License, the same license as the project.

---

## Questions?

If you have questions about contributing:
1. Check this document first
2. Search existing issues
3. Ask in Discussions
4. Contact maintainers

Thank you for helping improve the Aegis Implementation Guide!
