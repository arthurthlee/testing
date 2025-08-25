"""
Script to create or update GitHub issues for Dependabot security alerts.
This script fetches Dependabot alerts from the GitHub API and creates or updates issues
for each alert. If an issue already exists for a package, it appends the alert details
to the issue body, avoiding duplicates.
"""

import os
import json
import requests
from github import Github

# Define severity ranking
SEVERITY_ORDER = {"critical": 4, "high": 3, "moderate": 2, "low": 1, "unknown": 0}

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

    g = Github(token)
    repo = g.get_repo(repo_name)
    # Delete all existing issues with dependabot label
    delete_dependabot_github_issues(repo)

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

    # Collect all alerts for that same package
    package_alerts = [a for a in alerts if a.get("security_vulnerability", {}).get("package", {}).get("name", "").lower() == top_alert_package_name.lower()]

    print(f"Processing top severity alert for package: {top_alert_package_name} with {len(package_alerts)} total alerts")
    # Look for an existing open issue for this specific package
    dependabot_issues = list(repo.get_issues(state="open", labels=["dependabot"]))
    all_dependabot_issues = {}
    for issue in dependabot_issues:
        all_dependabot_issues[issue.number] = issue

    for alert in package_alerts:
        print(f"""
Processing Dependabot alert for:
{alert.get('security_vulnerability', {}).get('package', {}).get('name', 'Unknown package')}...
""")
        create_or_update_github_issue(repo, alert, all_dependabot_issues)



def create_or_update_github_issue(repo, alert, all_dependabot_issues):
    """
    Create or update a GitHub issue for a single Dependabot alert.

    Args:
        repo (github.Repository.Repository): Authenticated PyGithub repository object.
        alert (dict): JSON object representing a Dependabot security alert.

    Behavior:
        - If no issue exists for the package, create a new one.
        - If an issue exists, append the alert details to the body (avoiding duplicates).
    """
    security_vulnerability = alert.get("security_vulnerability", {})
    security_advisory = alert.get("security_advisory", {})
    package_name = (
        security_vulnerability
        .get("package", {})
        .get("name", "Unknown package")
    )
    severity = security_vulnerability.get("severity", "unknown")
    fixed_in = (
        security_vulnerability
        .get("first_patched_version", {})
        .get("identifier", "N/A")
    )
    advisory_url = alert.get("html_url", "No advisory link")
    alert_number = alert.get("number", "Unknown")

    # Create a unique identifier for this specific alert
    alert_id = f"<!-- alert-{alert_number} -->"


    new_alert_section = f"""
---

**Dependabot Alert #{alert_number}** - Security vulnerability in **{package_name}**

Summary: {security_advisory.get('summary', 'No summary available')}
Description: {security_advisory.get('description', 'No description available')}

**Severity:** {severity}
**Fixed in:** {fixed_in}

More details: [Security Advisory]({advisory_url})

<!-- {alert_id} -->

<details>
<summary>Full Vulnerability Details</summary>

{json.dumps(alert, indent=2)}

</details>
"""

    issue_title = f"Security vulnerability detected: {package_name}".lower()

    for issue in all_dependabot_issues.values():
        expected_title = f"Security vulnerability detected: {package_name}".lower()
        if issue.title.lower() == expected_title:
            update_github_issue(issue, new_alert_section, alert_id, alert_number, severity)
            return

    # If no existing issue found, create a new one
    print(f"No existing issue found for {package_name.lower()}, creating a new one...")
    issue = create_github_issue(
        repo,
        package_name.lower(),
        new_alert_section,
        severity,
        issue_title.lower()
    )
    all_dependabot_issues[issue.number] = issue



def create_github_issue(repo, package_name, new_alert_section, severity, issue_title):
    """
    Create a new issue.
    Args:
        repo (github.repo): The repo to create a new issue in.
        package_name (str): The name of the outdated package.
        new_alert_section (str): The alert text from the Dependabot alert
        that will be copied to the Github Issue.
        severity (str): The Dependabot severity of the alert.
        issue_title (str): Title of the issue to be created.
    """
    # No existing issue found → create new one
    initial_body = f"""
This issue tracks security vulnerabilities detected by Dependabot for the **{package_name}** package.

{new_alert_section}
"""

    # Create labels list including severity and open-swe
    issue_labels = ["dependabot", "open-swe"]

    # Add severity as a label if it's not unknown
    if severity and severity.lower() != "unknown":
        severity_label = f"severity-{severity.lower()}"
        issue_labels.append(severity_label)

    new_issue = repo.create_issue(
        title=issue_title,
        body=initial_body,
        labels=issue_labels
    )
    print(f"""
Issue created: {issue_title} (#{new_issue.number}) with labels: {', '.join(issue_labels)}
"""
    )
    return new_issue



def update_github_issue(issue, new_alert_section, alert_id, alert_number, severity):
    """
    Update an existing issue by appending new alert details.
    Avoids adding duplicate alert details.
    Args:
        issue (github.Issue.Issue): The existing issue to update.
        new_alert_section (str): The markdown section to append.
        alert_id (str): Unique identifier for the alert to avoid duplicates.
        alert_number (int): The Dependabot alert number.
        severity (str): Severity level of the vulnerability.
    """
    # Check if this specific alert is already in the issue
    if alert_id in issue.body:
        print(f"Alert #{alert_number} already exists in issue: {issue.title.lower()}")
        return
    print(f"Updating existing issue: {issue.title}")
    updated_body = issue.body.strip() + "\n" + new_alert_section

    # Update labels to include new severity if different and add open-swe if not present
    current_labels = [label.name for label in issue.labels]
    updated_labels = list(current_labels)  # Copy current label

    # Add open-swe label if not present
    if "open-swe" not in current_labels:
        updated_labels.append("open-swe")

    # Add severity label if not unknown and not already present
    if severity and severity.lower() != "unknown":
        severity_label = f"severity-{severity.lower()}"
        # Check if any severity label already exists
        if severity_label not in current_labels:
            updated_labels.append(severity_label)

    issue.edit(body=updated_body, labels=updated_labels)
    print(f"Updated issue with labels: {', '.join(updated_labels)}")



def delete_dependabot_github_issues(repo):
    """
    Delete all issues with the 'dependabot' label.
    Use with caution: this will delete issues permanently.
    """

    dependabot_issues = list(repo.get_issues(state="open", labels=["dependabot"]))

    for issue in dependabot_issues:
        print(f"Deleting issue: {issue.title} (#{issue.number})")
        issue.edit(state="closed", state_reason="duplicate")
        print(f"Issue #{issue.number} deleted.")

if __name__ == "__main__":
    main()
