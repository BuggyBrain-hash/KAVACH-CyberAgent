def verify_patch(original_findings, patched_findings):

    original_types = {
        finding["type"]
        for finding in original_findings
    }

    patched_types = {
        finding["type"]
        for finding in patched_findings
    }

    resolved = original_types - patched_types
    remaining = original_types & patched_types

    return {
        "resolved": sorted(resolved),
        "remaining": sorted(remaining),
        "original_count": len(original_findings),
        "patched_count": len(patched_findings),
        "success": len(remaining) == 0
    }