from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict
from typing import Any, Dict, Optional
from urllib.parse import urlparse
from html.parser import HTMLParser
import re


app = FastAPI(title="LLM Action Firewall")


ASSIGNED_TENANT = "tenant-7kjuzls"
ALLOWED_EMAIL_DOMAIN = "notify-x6o361v.example"

ALLOWED_TOOLS = {
    "search",
    "lookup_record",
    "send_email",
    "render_html",
}


# ============================================================
# HTML SAFETY CHECK
# ============================================================

class HTMLSafetyParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.unsafe = False

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()

        # Block dangerous tags
        if tag in {"script", "iframe"}:
            self.unsafe = True
            return

        for name, value in attrs:
            name = name.lower()

            # Block inline event handlers such as onclick, onload, etc.
            if name.startswith("on"):
                self.unsafe = True
                return

            # Block javascript: URLs
            if value:
                value_lower = value.strip().lower()

                if name in {
                    "href",
                    "src",
                    "action",
                    "formaction",
                    "xlink:href",
                }:
                    if value_lower.startswith("javascript:"):
                        self.unsafe = True
                        return


def is_safe_html(html: str) -> bool:
    parser = HTMLSafetyParser()

    try:
        parser.feed(html)
        parser.close()
    except Exception:
        return False

    return not parser.unsafe


# ============================================================
# RESPONSE HELPERS
# ============================================================

def allow():
    return {
        "decision": "allow",
        "reason": "ALLOW"
    }


def block(reason: str):
    return {
        "decision": "block",
        "reason": reason
    }


# ============================================================
# TOP LEVEL VALIDATION
# ============================================================

VALID_PROVENANCE = {"trusted", "untrusted"}

TOP_LEVEL_KEYS = {
    "provenance",
    "humanApproved",
    "untrustedContent",
    "action",
}

ACTION_KEYS = {
    "tool",
    "args",
}


def validate_top_level(data: Any):
    if not isinstance(data, dict):
        return False

    # Exact top-level fields
    if set(data.keys()) - TOP_LEVEL_KEYS:
        return False

    # Required fields
    if "provenance" not in data:
        return False

    if "humanApproved" not in data:
        return False

    if "action" not in data:
        return False

    # provenance
    if data["provenance"] not in VALID_PROVENANCE:
        return False

    # humanApproved must be a real boolean
    if type(data["humanApproved"]) is not bool:
        return False

    # optional untrustedContent
    if "untrustedContent" in data:
        if not isinstance(data["untrustedContent"], str):
            return False

    # action
    if not isinstance(data["action"], dict):
        return False

    if set(data["action"].keys()) != ACTION_KEYS:
        return False

    if not isinstance(data["action"]["tool"], str):
        return False

    if not isinstance(data["action"]["args"], dict):
        return False

    return True


# ============================================================
# TOOL ARGUMENT SCHEMA VALIDATION
# ============================================================

def exact_keys(obj: dict, expected: set) -> bool:
    return set(obj.keys()) == expected


def validate_search(args: dict) -> bool:
    if not exact_keys(args, {"query"}):
        return False

    query = args["query"]

    if not isinstance(query, str):
        return False

    if not (1 <= len(query) <= 200):
        return False

    return True


def validate_lookup_record(args: dict) -> bool:
    if not exact_keys(args, {"tenantId", "recordId"}):
        return False

    tenant_id = args["tenantId"]
    record_id = args["recordId"]

    if not isinstance(tenant_id, str):
        return False

    if not isinstance(record_id, str):
        return False

    if record_id == "":
        return False

    return True


def validate_send_email(args: dict) -> bool:
    if not exact_keys(args, {"to", "subject", "body"}):
        return False

    if not isinstance(args["to"], str):
        return False

    if not isinstance(args["subject"], str):
        return False

    if not isinstance(args["body"], str):
        return False

    if args["to"] == "":
        return False

    return True


def validate_render_html(args: dict) -> bool:
    if not exact_keys(args, {"html"}):
        return False

    if not isinstance(args["html"], str):
        return False

    return True


# ============================================================
# MAIN FIREWALL
# ============================================================

@app.post("/action-firewall")
async def action_firewall(data: Dict[str, Any]):

    # --------------------------------------------------------
    # 1. TOP-LEVEL SCHEMA
    # --------------------------------------------------------
    if not validate_top_level(data):
        return block("INVALID_SCHEMA")

    action = data["action"]
    tool = action["tool"]
    args = action["args"]

    # --------------------------------------------------------
    # 2. TOOL ALLOWLIST
    # --------------------------------------------------------
    if tool not in ALLOWED_TOOLS:
        return block("TOOL_NOT_ALLOWED")

    # --------------------------------------------------------
    # 3. SELECTED TOOL ARGUMENT SCHEMA
    # --------------------------------------------------------
    if tool == "search":
        if not validate_search(args):
            return block("INVALID_SCHEMA")

    elif tool == "lookup_record":
        if not validate_lookup_record(args):
            return block("INVALID_SCHEMA")

    elif tool == "send_email":
        if not validate_send_email(args):
            return block("INVALID_SCHEMA")

    elif tool == "render_html":
        if not validate_render_html(args):
            return block("INVALID_SCHEMA")

    # --------------------------------------------------------
    # 4. TENANT SCOPE
    # --------------------------------------------------------
    if tool == "lookup_record":
        if args["tenantId"] != ASSIGNED_TENANT:
            return block("TENANT_SCOPE")

    # --------------------------------------------------------
    # 5. EXACT EMAIL DOMAIN
    # --------------------------------------------------------
    if tool == "send_email":

        recipient = args["to"]

        # Basic deterministic email structure
        if recipient.count("@") != 1:
            return block("EGRESS_DENIED")

        local, domain = recipient.rsplit("@", 1)

        if not local or not domain:
            return block("EGRESS_DENIED")

        # Exact domain match
        if domain != ALLOWED_EMAIL_DOMAIN:
            return block("EGRESS_DENIED")

    # --------------------------------------------------------
    # 6. HUMAN APPROVAL
    # --------------------------------------------------------
    if tool == "send_email":
        if data["humanApproved"] is not True:
            return block("APPROVAL_REQUIRED")

    # --------------------------------------------------------
    # 7. HTML SAFETY
    # --------------------------------------------------------
    if tool == "render_html":
        if not is_safe_html(args["html"]):
            return block("UNSAFE_OUTPUT")

    # --------------------------------------------------------
    # EVERYTHING PASSED
    # --------------------------------------------------------
    return allow()


@app.get("/")
def root():
    return {
        "service": "LLM Action Firewall",
        "endpoint": "/action-firewall",
        "status": "ok"
    }
