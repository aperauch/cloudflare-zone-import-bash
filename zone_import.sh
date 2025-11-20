#!/usr/bin/env zsh

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
BLUE="\033[0;34m"
RESET="\033[0m"

log_info() {
  printf "%b\n" "${BLUE}[INFO]${RESET} $*"
}

log_success() {
  printf "%b\n" "${GREEN}[OK]${RESET} $*"
}

log_warn() {
  printf "%b\n" "${YELLOW}[WARN]${RESET} $*"
}

log_error() {
  printf "%b\n" "${RED}[ERROR]${RESET} $*" 1>&2
}

usage() {
  cat <<EOF
Usage: $0 -f <csv_file> [-t <cf_api_token>] [-a <cf_account_id>] [-o <output_csv>]

Options:
  -f, --file      Path to input CSV file (required)
  -t, --token     Cloudflare API token (overrides CF_API_TOKEN/.env)
  -a, --account   Cloudflare account ID (overrides CF_ACCOUNT_ID/.env)
  -o, --output    Output CSV file path (default: zone_import_results.csv)
  -h, --help      Show this help message
EOF
  exit 1
}

CSV_FILE=""
CLI_CF_API_TOKEN=""
CLI_CF_ACCOUNT_ID=""
OUTPUT_FILE="zone_import_results.csv"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -f|--file)
      CSV_FILE="$2"
      shift 2
      ;;
    -t|--token)
      CLI_CF_API_TOKEN="$2"
      shift 2
      ;;
    -a|--account)
      CLI_CF_ACCOUNT_ID="$2"
      shift 2
      ;;
    -o|--output)
      OUTPUT_FILE="$2"
      shift 2
      ;;
    -h|--help)
      usage
      ;;
    *)
      log_error "Unknown argument: $1"
      usage
      ;;
  esac
done

if [[ -z "$CSV_FILE" ]]; then
  log_error "CSV file is required."
  usage
fi

if [[ ! -f "$CSV_FILE" ]]; then
  log_error "CSV file '$CSV_FILE' not found."
  exit 1
fi

if [[ -f .env ]]; then
  log_info "Loading environment variables from .env"
  set -a
  source .env
  set +a
fi

if [[ -n "$CLI_CF_API_TOKEN" ]]; then
  CF_API_TOKEN="$CLI_CF_API_TOKEN"
fi

if [[ -n "$CLI_CF_ACCOUNT_ID" ]]; then
  CF_ACCOUNT_ID="$CLI_CF_ACCOUNT_ID"
fi

if [[ -z "${CF_API_TOKEN:-}" || -z "${CF_ACCOUNT_ID:-}" ]]; then
  log_error "CF_API_TOKEN and CF_ACCOUNT_ID must be provided via CLI or .env file."
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  log_error "curl is required but not installed."
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  log_error "jq is required but not installed. Please install jq and rerun."
  exit 1
fi

if command -v dig >/dev/null 2>&1; then
  DIG_AVAILABLE=1
else
  DIG_AVAILABLE=0
  log_warn "dig not found; DNSSEC checks will be skipped."
fi

if command -v whois >/dev/null 2>&1; then
  WHOIS_AVAILABLE=1
else
  WHOIS_AVAILABLE=0
  log_warn "whois not found; registrar checks will be skipped."
fi

CF_API_BASE="https://api.cloudflare.com/client/v4"

cf_api_request() {
  local method="$1"
  local path="$2"
  local data="${3:-}"

  if [[ -n "$data" ]]; then
    /usr/bin/curl -sS -X "$method" "${CF_API_BASE}${path}" \
      -H "Authorization: Bearer ${CF_API_TOKEN}" \
      -H "Content-Type: application/json" \
      --data "$data"
  else
    /usr/bin/curl -sS -X "$method" "${CF_API_BASE}${path}" \
      -H "Authorization: Bearer ${CF_API_TOKEN}" \
      -H "Content-Type: application/json"
  fi
}

to_lower() {
  echo "$1" | tr '[:upper:]' '[:lower:]'
}

normalize_bool() {
  local v
  v=$(echo "$1" | tr '[:upper:]' '[:lower:]' | xargs)
  case "$v" in
    true|yes|1)
      echo "true"
      ;;
    false|no|0|"")
      echo "false"
      ;;
    *)
      echo "$v"
      ;;
  esac
}

sanitize_csv_field() {
  local v="$1"
  v=${v//$'\n'/ }
  v=${v//$'\r'/ }
  echo "$v"
}

log_info "Using input CSV: $CSV_FILE"
log_info "Output CSV will be written to: $OUTPUT_FILE"

printf "%s\n" "Zone Name,Zone Type,License Type,Enable Foundation DNS,DNS Record Source,Enable Cloudflare Managed Ruleset,Bulk Redirect List ID,Zone ID,Zone Created Status,License Update Status,Foundation DNS Status,DNS Scan Status,Managed Ruleset Status,Bulk Redirect Status,DNSSEC Enabled,Registrar,Error" >"$OUTPUT_FILE"

tail -n +2 "$CSV_FILE" | tr -d '\r' | while IFS=',' read -r zone_name zone_type license_type enable_foundation_dns dns_record_source enable_managed_ruleset bulk_redirect_list_id rest; do
  zone_name=$(echo "$zone_name" | xargs)
  zone_type=$(echo "$zone_type" | xargs)
  license_type=$(echo "$license_type" | xargs)
  enable_foundation_dns=$(echo "$enable_foundation_dns" | xargs)
  dns_record_source=$(echo "$dns_record_source" | xargs)
  enable_managed_ruleset=$(echo "$enable_managed_ruleset" | xargs)
  bulk_redirect_list_id=$(echo "$bulk_redirect_list_id" | xargs)

  if [[ -z "$zone_name" ]]; then
    continue
  fi

  local_zone_created_status=""
  local_license_status="skipped"
  local_foundation_dns_status="skipped"
  local_dns_scan_status="skipped"
  local_managed_ruleset_status="skipped"
  local_bulk_redirect_status="skipped"
  local_dnssec_enabled="unknown"
  local_registrar="unknown"
  local_error_message=""

  log_info "Processing zone '$zone_name' (Type: $zone_type, License: $license_type)"

  lc_zone_type=$(to_lower "$zone_type")
  if [[ -z "$lc_zone_type" ]]; then
    lc_zone_type="full"
  fi

  create_payload=$(jq -n \
    --arg name "$zone_name" \
    --arg account_id "$CF_ACCOUNT_ID" \
    --arg type "$lc_zone_type" \
    '{name: $name, account: {id: $account_id}, type: $type}')

  create_resp=$(cf_api_request "POST" "/zones" "$create_payload")
  if [[ -z "$create_resp" ]]; then
    log_error "No response when creating zone $zone_name"
    local_zone_created_status="error"
    local_error_message="create zone: no response"
  else
    create_success=$(echo "$create_resp" | jq -r '.success // false')
    if [[ "$create_success" != "true" ]]; then
      create_err=$(echo "$create_resp" | jq -r '.errors[0].message // "Unknown error"')
      
      if [[ "$create_err" == *"already exists"* ]]; then
        log_info "Zone $zone_name already exists, looking up zone ID"
        list_resp=$(cf_api_request "GET" "/zones?name=${zone_name}")
        if [[ -n "$list_resp" ]]; then
          list_success=$(echo "$list_resp" | jq -r '.success // false')
          if [[ "$list_success" == "true" ]]; then
            zone_id=$(echo "$list_resp" | jq -r '.result[0].id // ""')
            if [[ -n "$zone_id" && "$zone_id" != "null" ]]; then
              log_success "Found existing zone $zone_name (ID: $zone_id)"
              local_zone_created_status="existing"
            else
              log_error "Could not find zone ID for existing zone $zone_name"
              local_zone_created_status="error"
              local_error_message="lookup zone: zone exists but not found in list"
            fi
          else
            log_error "Failed to lookup zone $zone_name"
            local_zone_created_status="error"
            local_error_message="lookup zone: api error"
          fi
        else
          log_error "No response when looking up zone $zone_name"
          local_zone_created_status="error"
          local_error_message="lookup zone: no response"
        fi
      else
        log_error "Failed to create zone $zone_name: $create_err"
        local_zone_created_status="error"
        local_error_message="create zone: $create_err"
      fi
    else
      zone_id=$(echo "$create_resp" | jq -r '.result.id')
      if [[ -z "$zone_id" || "$zone_id" == "null" ]]; then
        log_error "Zone ID not returned for $zone_name"
        local_zone_created_status="error"
        local_error_message="create zone: missing zone_id"
      else
        log_success "Created zone $zone_name (ID: $zone_id)"
        local_zone_created_status="success"
      fi
    fi
  fi

  if [[ -n "$zone_id" ]]; then
    lc_license_type=$(to_lower "$license_type")
    plan_id=""
    case "$lc_license_type" in
      free)
        plan_id="free"
        ;;
      pro)
        plan_id="pro"
        ;;
      business)
        plan_id="business"
        ;;
      enterprise)
        plan_id="enterprise"
        ;;
    esac

    if [[ -n "$plan_id" ]]; then
      sub_payload=$(jq -n --arg plan_id "$plan_id" '{rate_plan: {id: $plan_id}}')
      sub_resp=$(cf_api_request "PUT" "/zones/${zone_id}/subscription" "$sub_payload" 2>/dev/null)
      if [[ -z "$sub_resp" ]]; then
        log_warn "No response updating subscription for zone $zone_name"
        local_license_status="error"
        if [[ -z "$local_error_message" ]]; then
          local_error_message="license update: no response"
        fi
      else
        sub_success=$(echo "$sub_resp" | jq -r '.success // false')
        if [[ "$sub_success" == "true" ]]; then
          log_success "Updated license type for $zone_name to $license_type"
          local_license_status="success"
        else
          sub_err=$(echo "$sub_resp" | jq -r '.errors[0].message // "Unknown error"')
          log_warn "Failed to update license for $zone_name: $sub_err"
          local_license_status="error"
          if [[ -z "$local_error_message" ]]; then
            local_error_message="license update: $sub_err"
          fi
        fi
      fi
    fi
  fi

  if [[ -n "$zone_id" ]]; then
    enable_foundation_dns_bool=$(normalize_bool "$enable_foundation_dns")
    if [[ "$enable_foundation_dns_bool" == "true" || "$enable_foundation_dns_bool" == "false" ]]; then
      log_info "Checking current Foundation DNS status for $zone_name"
      get_dns_settings_resp=$(cf_api_request "GET" "/zones/${zone_id}/dns_settings" 2>/dev/null)
      if [[ -z "$get_dns_settings_resp" ]]; then
        log_warn "No response when checking Foundation DNS status for $zone_name"
        local_foundation_dns_status="error"
        if [[ -z "$local_error_message" ]]; then
          local_error_message="foundation dns check: no response"
        fi
      else
        get_dns_settings_success=$(echo "$get_dns_settings_resp" | jq -r '.success // false')
        if [[ "$get_dns_settings_success" == "true" ]]; then
          current_foundation_dns=$(echo "$get_dns_settings_resp" | jq -r '.result.foundation_dns // false')
          desired_foundation_dns="$enable_foundation_dns_bool"
          
          if [[ "$current_foundation_dns" == "$desired_foundation_dns" ]]; then
            log_info "Foundation DNS for $zone_name is already set to $desired_foundation_dns (no change needed)"
            local_foundation_dns_status="unchanged"
          else
            log_info "Foundation DNS for $zone_name is currently $current_foundation_dns, updating to $desired_foundation_dns"
            dns_settings_payload=$(jq -n --argjson value "$([[ "$desired_foundation_dns" == "true" ]] && echo true || echo false)" '{foundation_dns: $value}')
            dns_settings_resp=$(cf_api_request "PATCH" "/zones/${zone_id}/dns_settings" "$dns_settings_payload" 2>/dev/null)
            if [[ -z "$dns_settings_resp" ]]; then
              log_warn "No response updating Foundation DNS for $zone_name"
              local_foundation_dns_status="error"
              if [[ -z "$local_error_message" ]]; then
                local_error_message="foundation dns: no response"
              fi
            else
              dns_settings_success=$(echo "$dns_settings_resp" | jq -r '.success // false')
              if [[ "$dns_settings_success" == "true" ]]; then
                log_success "Updated Foundation DNS for $zone_name to $desired_foundation_dns"
                local_foundation_dns_status="success"
              else
                dns_settings_err=$(echo "$dns_settings_resp" | jq -r '.errors[0].message // "Unknown error"')
                log_warn "Failed to update Foundation DNS for $zone_name: $dns_settings_err"
                local_foundation_dns_status="error"
                if [[ -z "$local_error_message" ]]; then
                  local_error_message="foundation dns: $dns_settings_err"
                fi
              fi
            fi
          fi
        else
          get_dns_settings_err=$(echo "$get_dns_settings_resp" | jq -r '.errors[0].message // "Unknown error"')
          log_warn "Failed to check Foundation DNS status for $zone_name: $get_dns_settings_err"
          local_foundation_dns_status="error"
          if [[ -z "$local_error_message" ]]; then
            local_error_message="foundation dns check: $get_dns_settings_err"
          fi
        fi
      fi
    fi
  fi

  if [[ -n "$zone_id" ]]; then
    lc_dns_record_source=$(to_lower "$dns_record_source")
    if [[ "$lc_dns_record_source" == "auto" ]]; then
      log_info "Triggering DNS records async scan for $zone_name"
      trigger_resp=$(cf_api_request "POST" "/zones/${zone_id}/dns_records/scan/trigger" '{}' 2>/dev/null)
      if [[ -z "$trigger_resp" ]]; then
        log_warn "No response from DNS records scan trigger for $zone_name"
        local_dns_scan_status="error"
        if [[ -z "$local_error_message" ]]; then
          local_error_message="dns scan trigger: no response"
        fi
      else
        trigger_success=$(echo "$trigger_resp" | jq -r '.success // false')
        if [[ "$trigger_success" != "true" ]]; then
          trigger_err=$(echo "$trigger_resp" | jq -r '.errors[0].message // "Unknown error"')
          log_warn "DNS records scan trigger failed for $zone_name: $trigger_err"
          local_dns_scan_status="error"
          if [[ -z "$local_error_message" ]]; then
            local_error_message="dns scan trigger: $trigger_err"
          fi
        else
          max_attempts=10
          attempt=1
          records_json="[]"
          while [[ $attempt -le $max_attempts ]]; do
            log_info "Polling DNS records scan review for $zone_name (attempt $attempt/$max_attempts)"
            review_resp=$(cf_api_request "GET" "/zones/${zone_id}/dns_records/scan/review" "" 2>/dev/null)
            if [[ -z "$review_resp" ]]; then
              sleep 5
              attempt=$((attempt + 1))
              continue
            fi

            review_success=$(echo "$review_resp" | jq -r '.success // false')
            if [[ "$review_success" != "true" ]]; then
              sleep 5
              attempt=$((attempt + 1))
              continue
            fi

            records_json=$(echo "$review_resp" | jq -c '.result // []' 2>/dev/null)
            if [[ -z "$records_json" ]]; then
              records_json="[]"
            fi
            break
          done

          if [[ -z "$records_json" ]]; then
            records_json="[]"
          fi

          accepts_json=$(echo "$records_json" | jq -c --arg apex "$zone_name" '
            map(
              select(
                .type != "NS"
                or (
                  (.name | ascii_downcase) != ($apex | ascii_downcase)
                  and (.name | ascii_downcase) != (($apex + ".") | ascii_downcase)
                )
              ) | {id: .id}
            )
          ' 2>/dev/null)
          if [[ -z "$accepts_json" ]]; then
            accepts_json="[]"
          fi

          reject_ids_json=$(echo "$records_json" | jq -c --arg apex "$zone_name" '
            map(
              select(
                .type == "NS"
                and (
                  (.name | ascii_downcase) == ($apex | ascii_downcase)
                  or (.name | ascii_downcase) == (($apex + ".") | ascii_downcase)
                )
              ) | {id: .id}
            )
          ' 2>/dev/null)
          if [[ -z "$reject_ids_json" ]]; then
            reject_ids_json="[]"
          fi

          apply_payload=$(jq -n --argjson accepts "$accepts_json" --argjson rejects "$reject_ids_json" '{accepts: $accepts, rejects: $rejects}')
          apply_resp=$(cf_api_request "POST" "/zones/${zone_id}/dns_records/scan/review" "$apply_payload" 2>/dev/null)
          if [[ -z "$apply_resp" ]]; then
            log_warn "No response when applying DNS scan review for $zone_name"
            local_dns_scan_status="error"
            if [[ -z "$local_error_message" ]]; then
              local_error_message="dns scan review: no response"
            fi
          else
            apply_success=$(echo "$apply_resp" | jq -r '.success // false')
            if [[ "$apply_success" == "true" ]]; then
              log_success "Applied DNS scan results for $zone_name (accepted non-apex NS records, rejected apex NS records)"
              local_dns_scan_status="success"
            else
              apply_err=$(echo "$apply_resp" | jq -r '.errors[0].message // "Unknown error"')
              log_warn "Failed to apply DNS scan review for $zone_name: $apply_err"
              local_dns_scan_status="error"
              if [[ -z "$local_error_message" ]]; then
                local_error_message="dns scan review: $apply_err"
              fi
            fi
          fi
        fi
      fi
    fi
  fi

  if [[ -n "$zone_id" ]]; then
    enable_managed_ruleset_bool=$(normalize_bool "$enable_managed_ruleset")
    if [[ "$enable_managed_ruleset_bool" == "true" ]]; then
      entry_resp=$(cf_api_request "GET" "/zones/${zone_id}/rulesets/phases/http_request_firewall_managed/entrypoint" 2>/dev/null)
      ruleset_id=""
      if [[ -n "$entry_resp" ]]; then
        entry_success=$(echo "$entry_resp" | jq -r '.success // false')
        if [[ "$entry_success" == "true" ]]; then
          ruleset_id=$(echo "$entry_resp" | jq -r '.result.id // ""')
        fi
      fi

      if [[ -z "$ruleset_id" ]]; then
        create_ruleset_payload=$(jq -n '{name: "Zone WAF managed entrypoint", description: "Entry point ruleset for WAF managed rules", kind: "zone", phase: "http_request_firewall_managed", rules: [{action: "execute", action_parameters: {id: "efb7b8c949ac4650a09736fc376e9aee", version: "latest"}, expression: "true", description: "Execute the Cloudflare Managed Ruleset"}]}')
        create_ruleset_resp=$(cf_api_request "POST" "/zones/${zone_id}/rulesets" "$create_ruleset_payload" 2>/dev/null)
        if [[ -n "$create_ruleset_resp" ]]; then
          cr_success=$(echo "$create_ruleset_resp" | jq -r '.success // false')
          if [[ "$cr_success" == "true" ]]; then
            ruleset_id=$(echo "$create_ruleset_resp" | jq -r '.result.id // ""')
          else
            cr_err=$(echo "$create_ruleset_resp" | jq -r '.errors[0].message // "Unknown error"')
            log_warn "Failed to create WAF managed ruleset entrypoint for $zone_name: $cr_err"
          fi
        fi
      fi

      if [[ -n "$ruleset_id" ]]; then
        create_rule_payload=$(jq -n '{action: "execute", action_parameters: {id: "efb7b8c949ac4650a09736fc376e9aee", version: "latest"}, expression: "true", description: "Execute the Cloudflare Managed Ruleset"}')
        create_rule_resp=$(cf_api_request "POST" "/zones/${zone_id}/rulesets/${ruleset_id}/rules" "$create_rule_payload" 2>/dev/null)
        if [[ -n "$create_rule_resp" ]]; then
          rule_success=$(echo "$create_rule_resp" | jq -r '.success // false')
          if [[ "$rule_success" == "true" ]]; then
            log_success "Enabled Cloudflare Managed Ruleset for $zone_name"
            local_managed_ruleset_status="success"
          else
            rule_err=$(echo "$create_rule_resp" | jq -r '.errors[0].message // "Unknown error"')
            log_warn "Failed to enable Cloudflare Managed Ruleset for $zone_name: $rule_err"
            local_managed_ruleset_status="error"
            if [[ -z "$local_error_message" ]]; then
              local_error_message="managed ruleset: $rule_err"
            fi
          fi
        fi
      else
        if [[ "$local_managed_ruleset_status" != "error" ]]; then
          local_managed_ruleset_status="error"
          if [[ -z "$local_error_message" ]]; then
            local_error_message="managed ruleset: could not determine ruleset id"
          fi
        fi
      fi
    fi
  fi

  if [[ -n "$zone_id" && -n "$bulk_redirect_list_id" ]]; then
    redirect_item=$(jq -n \
      --arg source "$zone_name" \
      '{redirect: {source_url: $source, target_url: "https://www.transmedics.com", status_code: 301, preserve_query_string: false, include_subdomains: true, subpath_matching: true, preserve_path_suffix: false}}')
    redirect_payload=$(printf '[%s]' "$redirect_item")
    redirect_resp=$(cf_api_request "POST" "/accounts/${CF_ACCOUNT_ID}/rules/lists/${bulk_redirect_list_id}/items" "$redirect_payload" 2>/dev/null)
    if [[ -z "$redirect_resp" ]]; then
      log_warn "No response when adding bulk redirect for $zone_name"
      local_bulk_redirect_status="error"
      if [[ -z "$local_error_message" ]]; then
        local_error_message="bulk redirect: no response"
      fi
    else
      redirect_success=$(echo "$redirect_resp" | jq -r '.success // false')
      if [[ "$redirect_success" == "true" ]]; then
        log_success "Added bulk redirect list item for $zone_name"
        local_bulk_redirect_status="success"
      else
        redirect_err=$(echo "$redirect_resp" | jq -r '.errors[0].message // "Unknown error"')
        log_warn "Failed to add bulk redirect for $zone_name: $redirect_err"
        local_bulk_redirect_status="error"
        if [[ -z "$local_error_message" ]]; then
          local_error_message="bulk redirect: $redirect_err"
        fi
      fi
    fi
  fi

  if [[ "$DIG_AVAILABLE" -eq 1 ]]; then
    dnskey_output=$(dig +short DNSKEY "$zone_name" 2>/dev/null || true)
    if [[ -n "$dnskey_output" ]]; then
      local_dnssec_enabled="true"
      log_success "DNSSEC appears enabled for $zone_name"
    else
      local_dnssec_enabled="false"
      log_warn "DNSSEC does not appear enabled for $zone_name"
    fi
  else
    local_dnssec_enabled="unavailable"
  fi

  if [[ "$WHOIS_AVAILABLE" -eq 1 ]]; then
    whois_output=$(whois "$zone_name" 2>/dev/null || true)
    registrar=$(echo "$whois_output" | awk -F":" '/Registrar:/ {gsub(/^ +| +$/, "", $2); print $2; exit}')
    if [[ -z "$registrar" ]]; then
      registrar=$(echo "$whois_output" | awk -F":" '/Registrar Name:/ {gsub(/^ +| +$/, "", $2); print $2; exit}')
    fi
    if [[ -n "$registrar" ]]; then
      local_registrar="$registrar"
      log_info "Registrar for $zone_name: $local_registrar"
    else
      local_registrar="unknown"
      log_warn "Could not determine registrar for $zone_name"
    fi
  else
    local_registrar="unavailable"
  fi

  local_error_message=$(sanitize_csv_field "$local_error_message")

  printf "%s\n" "${zone_name},${zone_type},${license_type},${enable_foundation_dns},${dns_record_source},${enable_managed_ruleset},${bulk_redirect_list_id},${zone_id:-},${local_zone_created_status},${local_license_status},${local_foundation_dns_status},${local_dns_scan_status},${local_managed_ruleset_status},${local_bulk_redirect_status},${local_dnssec_enabled},${local_registrar},${local_error_message}" >>"$OUTPUT_FILE"

done

log_success "Processing complete. Results written to $OUTPUT_FILE"
