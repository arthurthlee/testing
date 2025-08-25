"""
Script to create or update GitHub issues for Dependabot security alerts.
This script fetches Dependabot alerts from the GitHub API and creates or updates issues
for each alert. If an issue already exists for a package, it appends the alert details
to the issue body, avoiding duplicates.
"""

import os
import json
import re
import requests
from github import Github

# Define severity ranking
SEVERITY_ORDER = {"critical": 4, "high": 3, "moderate": 2, "low": 1, "unknown": 0}

ALERT_ID_PATTERN = re.compile(r"<!-- alert-(\d+) -->")

def main():
    """
    Entry point for the script.
    """
    token = os.environ["TOKEN"]
    repo_name = os.environ["GITHUB_REPOSITORY"]

    print("Finding Dependency vulnerabilities...")

    # Query Dependabot alerts API
    url = f"https://api.github.com/repos/{repo_name}/dependabot/alerts"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    resp = requests.get(url, headers=headers, timeout=10)

    if resp.status_code != 200:
        print("Failed to fetch vulnerability alerts")
        raise RuntimeError(
            f"Failed to fetch alerts from repo {url} {resp.status_code} {resp.text}"
        )

    alerts = resp.json()
    print(f"Found {len(alerts)} alerts")

    # Find the alert with highest severity, breaking ties by earliest number
    alerts_sorted = sorted(
        alerts,
        key=lambda a: (
            -SEVERITY_ORDER.get(a.get("security_vulnerability", {}).get("severity", "unknown").lower(), 0),
            a.get("number", float("inf"))
        )
    )
    top_alert = alerts_sorted[0]
    top_alert_package_name = top_alert.get("security_vulnerability", {}).get("package", {}).get("name", "unknown")


    print(f"Top severity package: {top_alert_package_name}")

    # Collect all alerts for that same package
    package_alerts = [a for a in alerts if a.get("security_vulnerability", {}).get("package", {}).get("name", "").lower() == top_alert_package_name.lower()]

    g = Github(token)
    repo = g.get_repo(repo_name)

    print(f"Processing top severity alert for package: {top_alert_package_name} with {len(package_alerts)} total alerts")

    # Look for an existing open issue for this specific package
    dependabot_issues = list(repo.get_issues(state="open", labels=["dependabot"]))

    # If multiple issues exist, close all but one
    main_issue = None
    for issue in dependabot_issues:
        pkg_name = issue.title.lower().replace("security vulnerability detected: ", "")
        if pkg_name == top_alert_package_name and main_issue is None:
            main_issue = issue
        else:
            # Close irrelevant issues
            issue.edit(state="closed", state_reason="superseded")
            print(f"Closed irrelevant issue #{issue.number}")

    if main_issue:
        sync_issue_with_alerts(main_issue, package_alerts)
    else:
        create_issue_for_package(repo, top_alert_package_name, package_alerts)



def format_alert_section(alert):
    """Format an alert as a markdown section."""
    security_vulnerability = alert.get("security_vulnerability", {})
    security_advisory = alert.get("security_advisory", {})

    package_name = security_vulnerability.get("package", {}).get("name", "unknown")
    severity = security_vulnerability.get("severity", "unknown")
    fixed_in = security_vulnerability.get("first_patched_version", {}).get("identifier", "N/A")
    advisory_url = alert.get("html_url", "No advisory link")
    alert_number = alert.get("number", "unknown")
    alert_id = f"<!-- alert-{alert_number} -->"

    return f"""
---

**Dependabot Alert #{alert_number}** - Security vulnerability in **{package_name}**

Summary: {security_advisory.get('summary', 'No summary available')}
Description: {security_advisory.get('description', 'No description available')}

**Severity:** {severity}
**Fixed in:** {fixed_in}

More details: [Security Advisory]({advisory_url})

{alert_id}

<details>
<summary>Full Vulnerability Details</summary>

{json.dumps(alert, indent=2)}

</details>
"""




def create_issue_for_package(repo, pkg_name, pkg_alerts):
    """Create a new GitHub issue for the top severity package."""
    issue_title = f"Security vulnerability detected: {pkg_name}"
    alert_sections = [format_alert_section(alert) for alert in pkg_alerts]
    body = f"This issue tracks security vulnerabilities detected by Dependabot for **{pkg_name}**.\n\n"
    body += "\n".join(alert_sections)

    severities = set(
        alert.get("security_vulnerability", {}).get("severity", "unknown").lower()
        for alert in pkg_alerts
        if alert.get("security_vulnerability", {}).get("severity", "unknown").lower() != "unknown"
    )
    labels = ["dependabot", "open-swe"] + [f"severity-{s}" for s in severities]

    new_issue = repo.create_issue(title=issue_title, body=body, labels=labels)
    print(f"Created issue #{new_issue.number} for package {pkg_name}")



def sync_issue_with_alerts(issue, pkg_alerts):
    """Update issue body and labels, remove resolved alerts, close if empty."""
    active_alert_ids = {f"alert-{alert.get('number')}" for alert in pkg_alerts}
    body = issue.body or ""

    # Remove alert sections that are no longer active
    current_alert_ids = ALERT_ID_PATTERN.findall(body)
    for alert_id in current_alert_ids:
        if alert_id not in active_alert_ids:
            body = re.sub(
                rf"\n---.*?<!-- {alert_id} -->.*?</details>\n",
                "",
                body,
                flags=re.DOTALL
            )
            print(f"Removed alert {alert_id} from issue #{issue.number}")

    # Append new alerts
    existing_ids = set(ALERT_ID_PATTERN.findall(body))
    for alert in pkg_alerts:
        alert_number = alert.get("number")
        alert_id = f"alert-{alert_number}"
        if alert_id not in existing_ids:
            new_section = format_alert_section(alert)
            body += "\n" + new_section
            print(f"Appended new alert #{alert_number} to issue #{issue.number}")

    # Close issue if empty
    remaining_alert_ids = ALERT_ID_PATTERN.findall(body)
    if not remaining_alert_ids:
        issue.edit(state="closed", state_reason="resolved")
        print(f"Issue #{issue.number} has no remaining alerts, closed.")
        return

    # Update labels
    update_issue_labels(issue, pkg_alerts)
    issue.edit(body=body)
    print(f"Issue #{issue.number} synchronized.")


def update_issue_labels(issue, pkg_alerts):
    """Update labels to reflect current alerts and severities."""
    current_labels = {label.name for label in issue.labels}
    current_labels.add("dependabot")
    current_labels.add("open-swe")
    for alert in pkg_alerts:
        severity = alert.get("security_vulnerability", {}).get("severity", "unknown").lower()
        if severity != "unknown":
            current_labels.add(f"severity-{severity}")
    issue.edit(labels=list(current_labels))


if __name__ == "__main__":
    main()
