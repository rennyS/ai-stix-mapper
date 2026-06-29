"""Optional direct import into OpenCTI as a draft.

This always targets a draft workspace so nothing lands in the live knowledge
base without a human reviewing and validating it first. Requires OpenCTI 6.2+
(draft workspaces) and the `opencti` extra (`pip install ai-stix-mapper[opencti]`).
"""

from __future__ import annotations


def import_as_draft(
    bundle_json: str,
    url: str,
    token: str,
    draft_name: str,
) -> str:
    """Push a STIX bundle into a new OpenCTI draft workspace.

    Returns the draft workspace id so the user can open it in the UI for review.
    """
    try:
        from pycti import OpenCTIApiClient
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "pycti is not installed. Install with: pip install ai-stix-mapper[opencti]"
        ) from exc

    client = OpenCTIApiClient(url, token)

    if not hasattr(client, "set_draft_id"):
        raise RuntimeError(
            "This pycti version has no draft support. Upgrade to a release "
            "targeting OpenCTI 6.2+ (which introduced draft workspaces)."
        )

    draft_id = client.draft_workspace.create(name=draft_name)
    client.set_draft_id(draft_id)
    try:
        client.stix2.import_bundle_from_json(bundle_json, update=True)
    finally:
        # Clear the draft context so the client isn't left pinned to it.
        client.set_draft_id("")
    return draft_id
