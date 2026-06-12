#!/usr/bin/env python3
# =============================================================================
# IIW PROJECTOR (FedRAMP SSP Appendix M: Integrated Inventory Workbook)
# =============================================================================
# Reads the canonical inventory in ksi-signal.json and projects it into the
# column shape of the FedRAMP Integrated Inventory Workbook template. Emits
# a CSV with the IIW column headers so the same canonical layer that produces
# the KSI signal and the OSCAL Rev 5 SSP also produces the IIW.
#
# This is the fourth report this codebase derives from one source (KSI signal,
# OSCAL SSP, OSCAL POA&M, and this IIW). The point
# of the projector is architectural rather than functional: a portfolio
# consumer that already has the KSI signal does not need a separate IIW
# deliverable, but FedRAMP processes still expect one. Projecting it from
# the same source closes the gap without requiring the operator to maintain
# two truths.
#
# Inputs:
#   --signal PATH    KSI signal JSON (default: ksi-signal.json in CWD)
#   --output PATH    Output CSV path (default: iiw.csv)
#
# Output: a CSV whose columns match the FedRAMP IIW template (SSP Appendix M).
# Fields not applicable to a serverless cloud system (IPv4, MAC, NetBIOS,
# Hardware Make/Model, VLAN, Serial #) are emitted as empty strings, per the
# IIW template's "leave blank" guidance.
# =============================================================================

import argparse
import csv
import json
import sys
from pathlib import Path


# IIW column order, per FedRAMP SSP Appendix M Inventory tab (row 2).
IIW_COLUMNS = [
    "UNIQUE ASSET IDENTIFIER",
    "IPv4 or IPv6 Address",
    "Virtual",
    "Public",
    "DNS Name or URL",
    "NetBIOS Name",
    "MAC Address",
    "Authenticated Scan",
    "Baseline Configuration Name",
    "OS Name and Version",
    "Location",
    "Asset Type",
    "Hardware Make/Model",
    "In Latest Scan",
    "Software/Database Vendor",
    "Software/Database Name & Version",
    "Patch Level",
    "Diagram Label",
    "Comments",
    "Serial #/Asset Tag #",
    "VLAN/Network ID",
    "System Administrator/Owner",
    "Application Administrator/Owner",
    "Function",
    "End-of-Life",
]


def yes_no(value):
    """Render a Python bool as IIW's Yes/No literal."""
    if value is True:
        return "Yes"
    if value is False:
        return "No"
    return ""


def project_component(component, signal):
    """Project a single canonical-inventory component into an IIW row."""
    attrs = component.get("attributes") or {}
    global_id = component.get("global_id") or {}
    ownership = signal.get("ownership") or {}
    ctype = component.get("type", "")

    # Shared "any inventory" fields
    row = {col: "" for col in IIW_COLUMNS}
    row["UNIQUE ASSET IDENTIFIER"] = component.get("component_id", "")
    row["Virtual"] = "Yes"  # everything in cloud is virtual; IIW asks anyway
    row["Public"] = yes_no(attrs.get("public"))
    row["Baseline Configuration Name"] = attrs.get("baseline_configuration", "")
    row["Location"] = attrs.get("region", "")
    row["Asset Type"] = attrs.get("iiw_asset_type", ctype)
    row["In Latest Scan"] = "Yes"  # this build emitted the row, so it is in the latest scan
    row["Diagram Label"] = attrs.get("diagram_label", "")
    row["System Administrator/Owner"] = ownership.get("system_owner", "")
    row["Application Administrator/Owner"] = ownership.get("application_owner", "")
    row["Function"] = attrs.get("function", "")
    row["End-of-Life"] = attrs.get("end_of_life", "")

    # Cloud-specific fields where the canonical inventory has the answer
    native_id = component.get("native_id", "")
    if ctype in ("object_store", "cdn_distribution", "function"):
        row["DNS Name or URL"] = attrs.get("domain_name", native_id) or ""
        row["Authenticated Scan"] = "No"  # serverless cloud has no auth-scan equivalent

    if ctype == "function":
        row["OS Name and Version"] = attrs.get("runtime", "")

    # Software fields (npm and PyPI packages)
    if ctype in ("npm_package", "pypi_package"):
        name = attrs.get("name", "")
        version = attrs.get("version", "")
        row["Software/Database Vendor"] = "Open Source"
        row["Software/Database Name & Version"] = f"{name}@{version}" if name and version else name
        row["Patch Level"] = version
        row["Authenticated Scan"] = ""  # blank per IIW guidance for software

    # Static content fields
    if ctype == "html_artifact":
        sha = global_id.get("sha256", "")
        row["Comments"] = f"sha256:{sha}" if sha else ""
        row["Authenticated Scan"] = ""  # blank for static content

    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--signal", default="ksi-signal.json", help="KSI signal JSON (default: ksi-signal.json)")
    parser.add_argument("--output", default="iiw.csv", help="Output CSV path (default: iiw.csv)")
    args = parser.parse_args()

    signal_path = Path(args.signal)
    if not signal_path.exists():
        print(f"error: KSI signal not found at {signal_path}", file=sys.stderr)
        return 2
    try:
        signal = json.loads(signal_path.read_text())
    except json.JSONDecodeError as exc:
        print(f"error: {signal_path} is not valid JSON: {exc}", file=sys.stderr)
        return 2

    components = signal.get("components") or []
    rows = [project_component(c, signal) for c in components]

    output_path = Path(args.output)
    with output_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=IIW_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    print(f"iiw.csv: {len(rows)} component rows projected from {signal_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
