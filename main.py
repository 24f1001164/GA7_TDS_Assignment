from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict, List, Any

app = FastAPI()


class ReleaseGateRequest(BaseModel):
    target: str
    event: str
    ref: str
    workflow: Dict[str, Any]
    image: Dict[str, Any]


@app.get("/")
def root():
    return {"service": "release-gate", "status": "ok"}


@app.post("/release-gate")
def release_gate(req: ReleaseGateRequest):

    violations = []

    workflow = req.workflow
    image = req.image

    # --------------------------------------------------
    # 1. Permissions
    # --------------------------------------------------
    expected_permissions = {
        "contents": "read",
        "packages": "write",
        "id-token": "none",
    }

    permissions = workflow.get("permissions", {})

    if permissions != expected_permissions:
        violations.append("EXCESS_PERMISSION")

    # --------------------------------------------------
    # 2. Pull request trigger
    # --------------------------------------------------
    if req.event == "pull_request":
        if workflow.get("trigger") != "pull_request":
            violations.append("UNSAFE_PR_TRIGGER")

    # --------------------------------------------------
    # 3. Tests
    # --------------------------------------------------
    if (
        workflow.get("testsPassed") is not True
        or workflow.get("matrixComplete") is not True
        or workflow.get("failFast") is not False
    ):
        violations.append("TESTS_INCOMPLETE")

    # --------------------------------------------------
    # 4. GitHub Actions pinning
    # --------------------------------------------------
    actions = workflow.get("actions", [])

    for action in actions:
        owner = action.get("owner")
        ref = action.get("ref", "")

        # actions/* may use a version tag
        if owner == "actions":
            continue

        # Every third-party action must use a full
        # 40-character lowercase hexadecimal SHA.
        if not (
            isinstance(ref, str)
            and len(ref) == 40
            and all(c in "0123456789abcdef" for c in ref)
        ):
            violations.append("MUTABLE_ACTION")
            break

    # --------------------------------------------------
    # 5. Docker image hardening
    # --------------------------------------------------

    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    secret_mode = image.get("secretMode")

    if secret_mode not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")

    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # --------------------------------------------------
    # 6. Production requirements
    # --------------------------------------------------
    if req.target == "production":

        if req.event != "push" or req.ref != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")

        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    # --------------------------------------------------
    # Final decision
    # --------------------------------------------------
    decision = "promote" if len(violations) == 0 else "block"

    return {
        "decision": decision,
        "violations": violations
    }
