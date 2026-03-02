# CI/CD Integration Guide

This guide explains how to integrate the Enhanced AI-Powered Security Scanner into your CI/CD pipelines.

## Table of Contents

- [GitHub Actions](#github-actions)
- [GitLab CI](#gitlab-ci)
- [Jenkins](#jenkins)
- [CircleCI](#circleci)
- [Azure Pipelines](#azure-pipelines)
- [Bitbucket Pipelines](#bitbucket-pipelines)
- [Configuration](#configuration)
- [Best Practices](#best-practices)

---

## GitHub Actions

### Option 1: Use as GitHub Action (Recommended)

The easiest way to integrate is using our official GitHub Action:

```yaml
name: Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Security Scanner
        uses: ALxxy123/code-scan-sec@v3
        with:
          path: '.'
          ai-provider: 'gemini'
          enable-ai: 'true'
          output-format: 'all'
          gemini-api-key: ${{ secrets.GEMINI_API_KEY }}
          fail-on-critical: 'true'
          fail-on-secrets: 'true'

      - name: Upload Reports
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-reports
          path: output/
```

### Option 2: Use Pre-built Workflows

Copy the provided workflow files to your repository:

1. **Full Security Scan** (`.github/workflows/security-scan.yml`)
   - Runs on push to main/develop
   - Daily scheduled scans
   - Creates issues for critical findings
   - Uploads detailed reports

2. **Pull Request Scan** (`.github/workflows/security-scan-pr.yml`)
   - Scans only changed files in PRs
   - Posts results as PR comment
   - Blocks merge if critical issues found

### Option 3: Manual Installation

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install Security Scanner
        run: pip install security-scan-cli

      - name: Run Scan
        env:
          GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
        run: |
          security-scan scan \
            --path . \
            --ai-provider gemini \
            --output all

      - name: Upload Reports
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-reports
          path: output/
```

### Required Secrets

Add these secrets to your GitHub repository:

1. Go to **Settings → Secrets and variables → Actions**
2. Click **New repository secret**
3. Add one or more API keys:

```
GEMINI_API_KEY: your-gemini-api-key
OPENAI_API_KEY: your-openai-api-key (optional)
ANTHROPIC_API_KEY: your-anthropic-api-key (optional)
```

---

## GitLab CI

Create `.gitlab-ci.yml` in your repository root:

```yaml
stages:
  - security

security_scan:
  stage: security
  image: python:3.11
  before_script:
    - pip install security-scan-cli
  script:
    - |
      security-scan scan \
        --path . \
        --ai-provider gemini \
        --output all
  variables:
    GEMINI_API_KEY: ${GEMINI_API_KEY}
  artifacts:
    name: security-reports
    paths:
      - output/
    when: always
    expire_in: 30 days
  only:
    - merge_requests
    - main
    - develop

security_scan_scheduled:
  extends: security_scan
  only:
    - schedules
  script:
    - |
      security-scan scan \
        --path . \
        --ai-provider gemini \
        --output all
    - |
      # Fail on critical findings
      if [ -f output/report.json ]; then
        CRITICAL=$(jq '.summary.vulnerability_stats.by_severity.critical // 0' output/report.json)
        SECRETS=$(jq '.summary.total_secrets // 0' output/report.json)
        if [ "$CRITICAL" -gt 0 ] || [ "$SECRETS" -gt 0 ]; then
          echo "Critical security issues found!"
          exit 1
        fi
      fi
```

### GitLab CI Variables

Add these in **Settings → CI/CD → Variables**:

- `GEMINI_API_KEY`: Your Gemini API key (masked)
- `OPENAI_API_KEY`: (Optional)
- `ANTHROPIC_API_KEY`: (Optional)

---

## Jenkins

Create `Jenkinsfile` in your repository:

```groovy
pipeline {
    agent any

    environment {
        GEMINI_API_KEY = credentials('gemini-api-key')
    }

    stages {
        stage('Setup') {
            steps {
                sh 'pip install security-scan-cli'
            }
        }

        stage('Security Scan') {
            steps {
                sh '''
                    security-scan scan \
                        --path . \
                        --ai-provider gemini \
                        --output all
                '''
            }
        }

        stage('Check Results') {
            steps {
                script {
                    def report = readJSON file: 'output/report.json'
                    def critical = report.summary.vulnerability_stats.by_severity.critical ?: 0
                    def secrets = report.summary.total_secrets ?: 0

                    if (critical > 0 || secrets > 0) {
                        error("Critical security issues found!")
                    }
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'output/**', allowEmptyArchive: true
            publishHTML([
                reportName: 'Security Scan Report',
                reportDir: 'output',
                reportFiles: 'report.html',
                keepAll: true,
                alwaysLinkToLastBuild: true
            ])
        }
    }
}
```

### Jenkins Credentials

1. Go to **Manage Jenkins → Credentials**
2. Add credentials:
   - ID: `gemini-api-key`
   - Type: Secret text
   - Value: Your Gemini API key

---

## CircleCI

Create `.circleci/config.yml`:

```yaml
version: 2.1

executors:
  python-executor:
    docker:
      - image: cimg/python:3.11

jobs:
  security-scan:
    executor: python-executor
    steps:
      - checkout

      - run:
          name: Install Security Scanner
          command: pip install security-scan-cli

      - run:
          name: Run Security Scan
          command: |
            security-scan scan \
              --path . \
              --ai-provider gemini \
              --output all
          environment:
            GEMINI_API_KEY: ${GEMINI_API_KEY}

      - run:
          name: Check for Critical Issues
          command: |
            if [ -f output/report.json ]; then
              CRITICAL=$(jq '.summary.vulnerability_stats.by_severity.critical // 0' output/report.json)
              SECRETS=$(jq '.summary.total_secrets // 0' output/report.json)
              if [ "$CRITICAL" -gt 0 ] || [ "$SECRETS" -gt 0 ]; then
                echo "Critical security issues found!"
                exit 1
              fi
            fi

      - store_artifacts:
          path: output/
          destination: security-reports

      - store_test_results:
          path: output/

workflows:
  security:
    jobs:
      - security-scan:
          filters:
            branches:
              only:
                - main
                - develop

  nightly:
    triggers:
      - schedule:
          cron: "0 2 * * *"
          filters:
            branches:
              only: main
    jobs:
      - security-scan
```

### CircleCI Environment Variables

Add in **Project Settings → Environment Variables**:

- `GEMINI_API_KEY`
- `OPENAI_API_KEY` (optional)
- `ANTHROPIC_API_KEY` (optional)

---

## Azure Pipelines

Create `azure-pipelines.yml`:

```yaml
trigger:
  branches:
    include:
      - main
      - develop

pr:
  branches:
    include:
      - main
      - develop

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: '3.11'

  - script: |
      pip install security-scan-cli
    displayName: 'Install Security Scanner'

  - script: |
      security-scan scan \
        --path . \
        --ai-provider gemini \
        --output all
    env:
      GEMINI_API_KEY: $(GEMINI_API_KEY)
    displayName: 'Run Security Scan'

  - script: |
      if [ -f output/report.json ]; then
        CRITICAL=$(jq '.summary.vulnerability_stats.by_severity.critical // 0' output/report.json)
        SECRETS=$(jq '.summary.total_secrets // 0' output/report.json)
        if [ "$CRITICAL" -gt 0 ] || [ "$SECRETS" -gt 0 ]; then
          echo "##vso[task.logissue type=error]Critical security issues found!"
          exit 1
        fi
      fi
    displayName: 'Check Results'

  - task: PublishBuildArtifacts@1
    condition: always()
    inputs:
      PathtoPublish: 'output/'
      ArtifactName: 'security-reports'

schedules:
  - cron: "0 2 * * *"
    displayName: Daily Security Scan
    branches:
      include:
        - main
    always: true
```

### Azure Pipeline Variables

Add in **Pipelines → Library → Variable groups**:

- `GEMINI_API_KEY` (mark as secret)
- `OPENAI_API_KEY` (optional, secret)
- `ANTHROPIC_API_KEY` (optional, secret)

---

## Bitbucket Pipelines

Create `bitbucket-pipelines.yml`:

```yaml
image: python:3.11

pipelines:
  default:
    - step:
        name: Security Scan
        caches:
          - pip
        script:
          - pip install security-scan-cli
          - |
            security-scan scan \
              --path . \
              --ai-provider gemini \
              --output all
          - |
            if [ -f output/report.json ]; then
              CRITICAL=$(jq '.summary.vulnerability_stats.by_severity.critical // 0' output/report.json)
              SECRETS=$(jq '.summary.total_secrets // 0' output/report.json)
              if [ "$CRITICAL" -gt 0 ] || [ "$SECRETS" -gt 0 ]; then
                echo "Critical security issues found!"
                exit 1
              fi
            fi
        artifacts:
          - output/**

  branches:
    main:
      - step:
          name: Security Scan - Production
          caches:
            - pip
          script:
            - pip install security-scan-cli
            - |
              security-scan scan \
                --path . \
                --ai-provider gemini \
                --output all
          artifacts:
            - output/**

  pull-requests:
    '**':
      - step:
          name: Security Scan - PR
          caches:
            - pip
          script:
            - pip install security-scan-cli
            - |
              security-scan scan \
                --path . \
                --ai-provider gemini \
                --output all
          artifacts:
            - output/**
```

### Bitbucket Repository Variables

Add in **Repository settings → Pipelines → Repository variables**:

- `GEMINI_API_KEY` (secured)
- `OPENAI_API_KEY` (optional, secured)
- `ANTHROPIC_API_KEY` (optional, secured)

---

## Configuration

### Custom Configuration File

Create `config.yaml` in your repository root to customize scanning behavior:

```yaml
scan:
  entropy_threshold: 3.5
  max_file_size: 10485760
  enable_ai_verification: true
  enable_vulnerability_scan: true

ai:
  default_provider: gemini
  max_retries: 5
  timeout: 30

vulnerabilities:
  severity_levels:
    - critical
    - high
    - medium
  categories:
    - sql_injection
    - xss
    - command_injection

report:
  output_dir: output
  default_formats:
    - html
    - json
  auto_open_browser: false
```

### Environment-Specific Settings

**Development:**
```bash
security-scan scan --path . --no-ai --quiet
```

**Staging:**
```bash
security-scan scan --path . --ai-provider gemini --output json
```

**Production:**
```bash
security-scan scan --path . --ai-provider claude --output all
```

---

## Best Practices

### 1. Run on Multiple Triggers

```yaml
on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM
  workflow_dispatch:      # Manual trigger
```

### 2. Scan Changed Files Only in PRs

```bash
# Get changed files
git diff --name-only origin/main..HEAD | grep -E '\.(py|js|ts)$' > changed_files.txt

# Scan only those files
while read file; do
  security-scan scan --path "$file" --output json
done < changed_files.txt
```

### 3. Use Different Thresholds

**Pull Requests:** Block only on critical
```bash
security-scan scan --path . --fail-on critical
```

**Main Branch:** Block on high and above
```bash
security-scan scan --path . --fail-on high
```

### 4. Cache Dependencies

```yaml
- uses: actions/cache@v3
  with:
    path: ~/.cache/pip
    key: ${{ runner.os }}-pip-${{ hashFiles('**/requirements.txt') }}
```

### 5. Parallel Scanning

```yaml
strategy:
  matrix:
    scan-type: [secrets, vulnerabilities]
steps:
  - run: |
      if [ "${{ matrix.scan-type }}" = "secrets" ]; then
        security-scan scan --path . --no-vuln
      else
        security-scan scan --path . --no-ai
      fi
```

### 6. Notification on Failure

**Slack:**
```yaml
- name: Notify Slack
  if: failure()
  uses: slackapi/slack-github-action@v1
  with:
    payload: |
      {
        "text": "Security scan failed!",
        "blocks": [
          {
            "type": "section",
            "text": {
              "type": "mrkdwn",
              "text": "Security issues found in ${{ github.repository }}"
            }
          }
        ]
      }
  env:
    SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK }}
```

### 7. Baseline Comparison

```bash
# Save current scan as baseline
security-scan scan --path . --output json
cp output/report.json baseline.json

# Compare with baseline
security-scan scan --path . --output json
diff baseline.json output/report.json
```

### 8. Security Report as Check

```yaml
- name: Create Check
  uses: actions/github-script@v7
  with:
    script: |
      const report = require('./output/report.json');
      await github.rest.checks.create({
        owner: context.repo.owner,
        repo: context.repo.repo,
        name: 'Security Scan',
        head_sha: context.sha,
        status: 'completed',
        conclusion: report.summary.total_secrets > 0 ? 'failure' : 'success',
        output: {
          title: 'Security Scan Results',
          summary: `Found ${report.summary.total_secrets} secrets and ${report.summary.total_vulnerabilities} vulnerabilities`
        }
      });
```

---

## Troubleshooting

### Issue: API Rate Limits

**Solution:** Use exponential backoff and retries
```yaml
ai:
  max_retries: 10
  timeout: 60
```

### Issue: Large Repositories

**Solution:** Exclude unnecessary directories
```bash
security-scan scan --path . --exclude node_modules,venv,dist
```

### Issue: False Positives

**Solution:** Use AI verification
```bash
security-scan scan --path . --ai-provider gemini
```

---

## Support

- **Issues**: https://github.com/ALxxy123/code-scan-sec/issues
- **Discussions**: https://github.com/ALxxy123/code-scan-sec/discussions
- **Documentation**: https://github.com/ALxxy123/code-scan-sec/tree/main/docs

---

**Happy Securing! 🛡️**
