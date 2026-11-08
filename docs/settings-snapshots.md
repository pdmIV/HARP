# Configuration snapshots

Open **Configuration → Configuration snapshots** to save or restore the application settings as a separate portable JSON file.

## Export

Save any changes in the model, oracle, and configuration tabs first, then click **Export saved settings**. The downloaded `harp-settings-<timestamp>.json` contains:

- The complete saved configuration, including advanced fields not displayed in the forms, authorized scope, runtime, WSL distribution/user, model choices, API endpoints, cache settings, prices, budgets, and experimental toggles.
- Unsloth launch settings when configured, including context, KV cache types, port, and parallelism.
- Current interface preferences: theme, experiment mode, replay speed, idle-gap shortening, refresh-reconnaissance choice, and the API-key provider selected in the import dropdown.

Export uses the configuration saved on the server plus the interface preferences currently selected in your browser. Unsaved form edits are not included. Save tab changes before exporting. Commands, delegated task drafts, search/filter text, the current tab, selected session, and replay position are transient views rather than saved application settings.

API keys are excluded by default. Select **Include saved API keys in the backup** to include imported keys from `.secrets`. Such backups contain readable credentials. Protect the downloaded file and any recovery copies. Environment-variable values, the dashboard access token, sessions, artifacts, logs, model weights, installed tools, VPN routes, and Codex/MCP approval policies are not included.

## Restore

1. Stop active/reconnaissance sessions and any model managed by HARP. Finish dependency installation. Exit recorded replay before using the snapshot controls.
2. Click **Choose backup file** and select a version-1 HARP settings snapshot. Files are limited to 48 KiB. Unsupported formats, malformed JSON, invalid settings, nonfinite values, and invalid included key data are rejected.
3. Review the summary and expand **All settings in this backup** for the complete configuration and interface preferences. Key values are not shown.
4. If the backup contains keys and you want to import them, select **Also restore the API keys included in this file**. This is off by default. Otherwise current keys are preserved.
5. Click **Apply backup settings**. HARP validates again, creates a pre-restore backup, replaces the saved configuration, refreshes the form controls, and applies the interface preferences. No model, session, network scan, installation, or root command is started.

Restoration replaces the configuration rather than merging it with the current file. Settings absent from the backup use application defaults; old advanced settings do not silently survive. Included API keys are imported through the normal platform-specific storage: Windows DPAPI or owner-only Linux files. Providers absent from the key map retain their current keys; restoring a backup does not delete credentials. Environment keys continue to take precedence over imported keys.

Runtime selections are preserved exactly. A WSL backup applied on native Kali still selects WSL until you change it. Review runtime-specific paths, distribution/user, target, and available models when moving between machines. Snapshot restoration does not verify API account access or reproduce external machine configuration.

Interface preferences persist in the current browser. A restored copy is also saved with the server configuration so a fresh browser can initialize them. Later browser preference changes take precedence in that browser. The one-shot refresh-reconnaissance preference clears after a session starts.

## Recovery and failure handling

After a successful restore, click **Download pre-restore backup** to download the previous settings. Recovery copies are also retained under `.settings_backups` next to `harp.json`; this directory is ignored by Git. If included keys were restored, the recovery copy includes the previous saved keys and therefore contains readable credentials too. These files have mode 600 in a mode-700 directory on Linux. Windows copies inherit the workspace's access controls.

All validation happens before settings or keys change. Configuration writes use atomic replacement. If restoring several keys or writing configuration fails, HARP attempts to put the original key files and configuration back. It reports explicitly if rollback cannot complete. The recovery copy remains available. Newly introduced key providers are not removed by applying a recovery snapshot, because key restoration imports the listed providers rather than deleting unlisted ones.

Snapshot operations use the command center's authenticated API. They do not mark human tactical intervention or alter saved session configurations and evidence. No account keys are loaded during a normal settings-only export.

## Verification

```bash
python3 -m unittest discover -s tests -p test_snapshots.py
node tests/test_web_ui.js
```

Tests cover complete configuration replacement, advanced settings, recovery copies, malformed files, key exclusion, opt-in key handling, partial-failure rollback, active-session blocking, UI preview, preference restoration, and downloads. They use temporary files and synthetic credentials without contacting model providers or targets. The file-permission check runs on Linux.
