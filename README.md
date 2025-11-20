# Cloudflare Zone Import Script

This project contains a `zsh` script that creates Cloudflare zones from a CSV file, configures plan / features, optionally runs DNS scans, enables the Cloudflare Managed Ruleset, adds bulk redirects, and gathers DNSSEC / registrar information.

## Prerequisites

- macOS (script uses `zsh`)
- `curl`
- `jq`
- Optional but recommended:
  - `dig` (for DNSSEC checks)
  - `whois` (for registrar lookup)

## Configuration

1. Create a `.env` file in this directory with:

   ```bash
   CF_API_TOKEN=your_api_token_here
   CF_ACCOUNT_ID=your_account_id_here
   ```

   The script will automatically load `.env`. You can also override these values via CLI arguments.

2. Prepare an input CSV file (for example `import_zones.csv`) with a header row matching:

   ```text
   Zone Name,Zone Type,License Type,Enable Foundation DNS,DNS Record Source,Enable Cloudflare Managed Ruleset,Bulk Redirect List ID
   ```

   - `Zone Name`: e.g. `example.com`
   - `Zone Type`: `Full`, `Partial`, `Secondary`, etc. (case-insensitive; defaults to `full` if empty)
   - `License Type`: `Free`, `Pro`, `Business`, or `Enterprise`
   - `Enable Foundation DNS`: `True` / `False` (case-insensitive)
   - `DNS Record Source`: set to `Auto` to trigger DNS quick scan
   - `Enable Cloudflare Managed Ruleset`: `True` / `False`
   - `Bulk Redirect List ID`: ID of an existing Bulk Redirect List in your account

## Script usage

From the project directory:

1. Make the script executable (once):

   ```bash
   chmod +x zone_import.sh
   ```

2. Run with a CSV file (using `.env` for credentials):

   ```bash
   ./zone_import.sh -f import_zones.csv
   ```

3. Or run with explicit credentials:

   ```bash
   ./zone_import.sh -f import_zones.csv \
     -t "$CF_API_TOKEN" \
     -a "$CF_ACCOUNT_ID"
   ```

## What the script does

For each row in the CSV:

- Creates a zone using `Zone Name` and `Zone Type`.
- Attempts to set the zone subscription (license) from `License Type`.
- Attempts to enable/disable Foundation DNS from `Enable Foundation DNS`.
- If `DNS Record Source` is `Auto`:
  - Triggers an async DNS records quick scan.
  - Polls the scan review endpoint.
  - Accepts all discovered records **except** NS records at the apex (those NS records are explicitly rejected).
- If `Enable Cloudflare Managed Ruleset` is true:
  - Ensures a zone ruleset exists for `http_request_firewall_managed`.
  - Adds a rule to execute the Cloudflare Managed Ruleset.
- If `Bulk Redirect List ID` is present:
  - Adds a Bulk Redirect item for the zone pointing to `https://www.transmedics.com` with the configured parameters.
- Uses `dig` (if available) to check whether DNSSEC appears enabled.
- Uses `whois` (if available) to capture the registrar.
- Writes results to `zone_import_results.csv` and prints colored status messages to the terminal.
