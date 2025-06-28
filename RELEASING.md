# Release

Releases are handled by the `Release` GitHub Actions workflow. The workflow must be triggered manually, either from the web UI or the GitHub CLI.

## 1. Refresh (or Create) the Charmhub Token

The workflow needs a valid Charmhub token stored in the repository secrets.

```bash
# Authenticate with Charmhub and export credentials
charmcraft login --export creds

# Save the token as a repository secret
gh secret set CHARMHUB_TOKEN < creds
```

Regenerate and re-upload the token whenever it expires.

## 2. Trigger the Release Workflow

Run the workflow from the command line—or start it from **Actions ➜ Release** in the GitHub web UI:

```bash
gh workflow run Release
```

Select the appropriate channel for the new release and you're done! The action builds and pushes the new charm release to Charmhub.
