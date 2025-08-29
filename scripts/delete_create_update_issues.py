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

    print("Fetching Dependabot alerts...")
    alerts = fetch_dependabot_alerts(repo_name, token)
    open_alerts = [a for a in alerts if a.get("state") == "open"]

    if not open_alerts:
        print("No alerts found.")
    print(f"Found {len(open_alerts)} alerts")

    g = Github(token)
    repo = g.get_repo(repo_name)

    # Look for an existing open issue for this specific package
    dependabot_issues = list(repo.get_issues(state="open", labels=["dependabot"]))
    existing_issue = next(iter(dependabot_issues), None)

    if not open_alerts:
        # If no alerts, close the existing issue
        if existing_issue:
            print(f"Closing issue #{existing_issue.number}, no open alerts remain")
            existing_issue.edit(state="closed", state_reason="completed")
        return

    # Find the alert with highest severity, breaking ties by earliest number
    alerts_sorted = sorted(
        open_alerts,
        key=lambda a: (
            -SEVERITY_ORDER.get(
                a["security_vulnerability"].get("severity", "unknown").lower(),
                0
            ),
            a.get("number", float("inf"))
        )
    )
    top_alert = alerts_sorted[0]
    top_alert_pkg_name = top_alert["security_vulnerability"]["package"]["name"].lower()

    print(f"Top severity package: {top_alert_pkg_name}")

    # Collect all alerts for that same package
    package_alerts = [
        a for a in alerts \
            if a["security_vulnerability"]["package"]["name"].lower() == top_alert_pkg_name.lower()]

    print(f"Processing top severity alert for package: \
{top_alert_pkg_name} with {len(package_alerts)} total alerts")

    # If multiple issues exist, close all but one
    main_issue = None
    for issue in dependabot_issues:
        pkg_name = issue.title.lower().replace("security vulnerability detected: ", "")
        if pkg_name == top_alert_pkg_name and main_issue is None:
            main_issue = issue
        else:
            # Close irrelevant issues
            issue.edit(state="closed", state_reason="not_planned")
            print(f"Closed irrelevant issue #{issue.number}")

    if main_issue:
        sync_issue_with_alerts(main_issue, package_alerts)
    else:
        create_issue_for_package(repo, top_alert_pkg_name, package_alerts)



def fetch_dependabot_alerts(repo_name, token):
    """Fetch Dependabot alerts from GitHub API."""
    url = f"https://api.github.com/repos/{repo_name}/dependabot/alerts"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        print(f"Failed to fetch alerts: {e}")
        return []



def format_alert_section(alert):
    """Format an alert as a markdown section."""
    security_vulnerability = alert["security_vulnerability"]
    security_advisory = alert["security_advisory"]

    package_name = security_vulnerability["package"]["name"]
    severity = security_vulnerability.get("severity", "unknown")
    fixed_in = security_vulnerability.get("first_patched_version", {}).get("identifier", "N/A")
    advisory_url = alert.get("html_url", "No advisory link")
    alert_number = alert.get("number", "unknown")
    alert_id = f"<!-- alert-{alert_number} -->"

    return f"""
---

{alert_id}

**Dependabot Alert #{alert_number}** - Security vulnerability in **{package_name}**

Summary: {security_advisory.get('summary', 'No summary available')}
Description: {security_advisory.get('description', 'No description available')}

**Severity:** {severity}
**Fixed in:** {fixed_in}

More details: [Security Advisory]({advisory_url})

<details>
<summary>Full Vulnerability Details</summary>

{json.dumps(alert, indent=2)}

</details>
"""



def create_issue_for_package(repo, pkg_name, pkg_alerts):
    """Create a new GitHub issue for the top severity package."""
    issue_title = f"Security vulnerability detected: {pkg_name}"
    alert_sections = [format_alert_section(alert) for alert in pkg_alerts]
    body = f"This issue tracks security vulnerabilities detected by Dependabot for \
**{pkg_name}**. We need to update the packages, and apply code fixes where necessary in the application. \
We need to pin the package version to the latest version compatible with the application code, but not any newer.\n\n"
    body += "\n".join(alert_sections)

    severities = set(
        alert["security_vulnerability"].get("severity", "unknown").lower()
        for alert in pkg_alerts
        if alert["security_vulnerability"].get("severity", "unknown").lower() != "unknown"
    )
    labels = ["dependabot", "swe-agent"] + [f"severity-{s}" for s in severities]

    new_issue = repo.create_issue(title=issue_title, body=body, labels=labels)
    print(f"Created issue #{new_issue.number} for package {pkg_name}")



def sync_issue_with_alerts(issue, pkg_alerts):
    """Update issue body and labels, remove resolved alerts, close if empty."""
    active_alert_ids = {f"alert-{alert['number']}" for alert in pkg_alerts}
    body = issue.body or ""

    # Remove alert sections that are no longer active
    current_alert_ids = ALERT_ID_PATTERN.findall(body)
    for alert_id in current_alert_ids:
        if alert_id not in active_alert_ids:
            body = re.sub(
                rf"\n---.*?<!-- alert-{alert_id} -->.*?</details>\n",
                "",
                body,
                flags=re.DOTALL
            )
            print(f"Removed alert {alert_id} from issue #{issue.number}")

    # Append new alerts
    existing_ids = set(ALERT_ID_PATTERN.findall(body))
    for alert in pkg_alerts:
        alert_number = alert["number"]
        alert_id = f"alert-{alert_number}"
        if alert_id not in existing_ids:
            new_section = format_alert_section(alert)
            body += "\n" + new_section
            print(f"Appended new alert #{alert_number} to issue #{issue.number}")

    # Close issue if empty
    remaining_alert_ids = ALERT_ID_PATTERN.findall(body)
    if not remaining_alert_ids:
        issue.edit(state="closed", state_reason="completed")
        print(f"Issue #{issue.number} has no remaining alerts, closed.")
        return

    # Update labels and body in single call
    current_labels = {label.name for label in issue.labels}
    current_labels.add("dependabot")
    current_labels.add("swe-agent")
    for alert in pkg_alerts:
        severity = alert.get("security_vulnerability", {}).get("severity", "unknown").lower()
        if severity != "unknown":
            current_labels.add(f"severity-{severity}")

    # Single edit call with both body and labels
    issue.edit(body=body, labels=list(current_labels))
    print(f"Issue #{issue.number} synchronized.")



if __name__ == "__main__":
    main()
