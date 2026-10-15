#!/usr/bin/env python3
"""
Restructure case 1 new.zip from flat layout (root JSON + images/) to UFDR-style
layout matching case 7: Artifacts/*, Media/Images/, Reports/, __metadata__/.
"""
from __future__ import annotations

import json
import re
import shutil
from datetime import datetime
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

BASE = Path(__file__).resolve().parent.parent / "data" / "UFDR's(new)"
SRC_NAME = "case 1 new.zip"
BACKUP_SUFFIX = ".flat_layout_backup.zip"


def _parse_whatsapp_blobs(raw: str) -> list:
    """whatsapp.json may contain multiple JSON arrays (e.g. markdown sections); merge them."""
    merged: list = []
    dec = json.JSONDecoder()
    i = 0
    while True:
        j = raw.find("[", i)
        if j < 0:
            break
        try:
            obj, end = dec.raw_decode(raw, j)
        except json.JSONDecodeError:
            i = j + 1
            continue
        if isinstance(obj, list):
            merged.extend(obj)
        i = end
    return merged


def _duration_to_seconds(d: object) -> int:
    if isinstance(d, int):
        return d
    if isinstance(d, float):
        return int(d)
    if not d:
        return 0
    s = str(d).strip()
    if s.isdigit():
        return int(s)
    m = re.match(r"^(\d{1,2}):(\d{2})(?::(\d{2}))?$", s)
    if m:
        parts = [int(x) for x in m.groups() if x is not None]
        if len(parts) == 2:
            return parts[0] * 60 + parts[1]
        return parts[0] * 3600 + parts[1] * 60 + parts[2]
    return 0


def _standardize_ts(ts: str) -> str:
    if isinstance(ts, str) and re.match(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", ts):
        return ts.replace(" ", "T", 1)
    return ts


def normalize_calls(data: list) -> list:
    out = []
    for c in data:
        if not isinstance(c, dict):
            continue
        row = dict(c)
        if "from" not in row and "sender_number" in row:
            row["from"] = str(row["sender_number"])
        if "to" not in row and "receiver_number" in row:
            row["to"] = str(row["receiver_number"])
        if "duration" in row:
            row["duration"] = _duration_to_seconds(row["duration"])
        if "timestamp" in row:
            row["timestamp"] = _standardize_ts(row["timestamp"])
        if "type" not in row:
            row["type"] = "outgoing"
        out.append(row)
    return out


def normalize_sms(data: list) -> list:
    out = []
    for m in data:
        if not isinstance(m, dict):
            continue
        row = dict(m)
        if "sender" in row and "from" not in row:
            row["from"] = row.pop("sender")
        if "receiver" in row and "to" not in row:
            row["to"] = row.pop("receiver")
        if "message" in row and "text" not in row:
            row["text"] = row.pop("message")
        if "timestamp" in row:
            row["timestamp"] = _standardize_ts(row["timestamp"])
        out.append(row)
    return out


def normalize_whatsapp(data: list) -> list:
    out = []
    for m in data:
        if not isinstance(m, dict):
            continue
        row = dict(m)
        if "sender" in row and "from" not in row:
            row["from"] = row.pop("sender")
        if "receiver" in row and "to" not in row:
            row["to"] = row.pop("receiver")
        if "message" in row and "text" not in row:
            row["text"] = row.pop("message")
        if "timestamp" in row:
            row["timestamp"] = _standardize_ts(row["timestamp"])
        out.append(row)
    return out


def main() -> None:
    src = BASE / SRC_NAME
    if not src.exists():
        raise SystemExit(f"Missing source: {src}")

    backup = BASE / (src.stem + BACKUP_SUFFIX)
    if not backup.exists():
        shutil.copy2(src, backup)
        print(f"Backup: {backup}")

    generated = datetime.now().isoformat()

    with ZipFile(src, "r") as zin:
        calls = normalize_calls(json.loads(zin.read("calls.json")))
        contacts = json.loads(zin.read("contacts.json"))
        sms = normalize_sms(json.loads(zin.read("sms.json")))
        wa_raw = zin.read("whatsapp.json").decode("utf-8")
        whatsapp = normalize_whatsapp(_parse_whatsapp_blobs(wa_raw))

        image_members = sorted(
            n for n in zin.namelist() if n.startswith("images/") and not n.endswith("/")
        )

    case_info = {
        "case_id": "KDN-C1-001",
        "case_type": "Kidnapping / weapons conspiracy (Case 1)",
        "officer": "Inspector Meera Joshi",
        "officer_id": "IPS-2019-442",
        "department": "Anti-Kidnapping Unit",
        "incident_date": "2026-04-18T08:00:00",
        "victim_name": "Withheld",
        "location": "Warehouse district, NCR",
        "description": (
            "Investigation into coordinated kidnapping and weapons-related activity. "
            "Communications reference meetups, warehouse movements, and logistics. "
            "Device media includes firearms-related imagery and identifiers consistent with the case file."
        ),
        "evidence_tags": [
            "kidnapping",
            "conspiracy",
            "weapons_imagery",
            "logistics",
            "sms",
            "whatsapp",
            "call_logs",
        ],
        "suspects": [],
        "priority": "High",
        "status": "Under Investigation",
        "created_at": generated,
        "last_updated": generated,
    }

    device_info = {
        "owner": "Primary device owner (Case 1)",
        "device_model": "Generic Android handset",
        "device_serial": "CASE1-UFDR-001",
        "imei": "350000000000001",
        "android_version": "Android 13",
        "manufacturer": "Unknown",
        "carrier": "Unknown",
        "phone_number": "+919458305432",
        "extraction_method": "Logical export (simulated)",
        "extraction_tool": "UFDR layout restructure",
        "extraction_time": generated,
        "extraction_location": "Forensic lab",
        "extraction_officer": "EVI tooling",
    }

    summary = {
        "generated_at": generated,
        "message_count": len(sms) + len(whatsapp),
        "whatsapp_count": len(whatsapp),
        "call_count": len(calls),
        "contact_count": len(contacts),
        "image_count": len(image_members),
    }

    log_txt = (
        "Extraction Log\n"
        f"Generated at: {generated}\n"
        "Tool: EVI restructure_case1_new_zip.py\n"
        "Notes: Converted from flat ZIP (root JSON + images/) to UFDR-style layout.\n"
    )

    report_html = f"""<html><head><title>Case 1 - Report</title></head><body>
<h1>Case 1 - Simulated Report</h1>
<p>Generated: {generated}</p>
<ul>
<li>Messages (SMS + WhatsApp): {summary['message_count']}</li>
<li>WhatsApp messages: {summary['whatsapp_count']}</li>
<li>Call logs: {summary['call_count']}</li>
<li>Contacts: {summary['contact_count']}</li>
<li>Images: {summary['image_count']}</li>
</ul>
</body></html>"""

    tmp = src.with_suffix(".zip.tmp")
    try:
        with ZipFile(tmp, "w", compression=ZIP_DEFLATED) as zout:
            zout.writestr(
                "Artifacts/Calls/calls.json",
                json.dumps(calls, indent=2, ensure_ascii=False) + "\n",
            )
            zout.writestr(
                "Artifacts/Contacts/contacts.json",
                json.dumps(contacts, indent=2, ensure_ascii=False) + "\n",
            )
            zout.writestr(
                "Artifacts/SMS/sms.json",
                json.dumps(sms, indent=2, ensure_ascii=False) + "\n",
            )
            zout.writestr(
                "Artifacts/WhatsApp/whatsapp.json",
                json.dumps(whatsapp, indent=2, ensure_ascii=False) + "\n",
            )
            zout.writestr(
                "__metadata__/case_info.json",
                json.dumps(case_info, indent=2, ensure_ascii=False) + "\n",
            )
            zout.writestr(
                "__metadata__/device_info.json",
                json.dumps(device_info, indent=2, ensure_ascii=False) + "\n",
            )
            zout.writestr("__metadata__/log.txt", log_txt)
            zout.writestr("Reports/summary.json", json.dumps(summary, indent=2) + "\n")
            zout.writestr("Reports/report.html", report_html)

            with ZipFile(src, "r") as zin:
                for i, name in enumerate(image_members, start=1):
                    ext = Path(name).suffix.lower() or ".jpg"
                    new_name = f"Media/Images/IMG_{i}{ext}"
                    zout.writestr(new_name, zin.read(name))

        tmp.replace(src)
        print(f"Wrote restructured: {src}")
        print(f"  Artifacts: calls, contacts, sms, whatsapp")
        print(f"  Media/Images: {len(image_members)} files")
        print(f"  __metadata__ + Reports")
    finally:
        if tmp.exists():
            tmp.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
