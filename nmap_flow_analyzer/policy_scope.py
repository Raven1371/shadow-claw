"""Approved source/destination network enforcement.

Every candidate rule is checked against the most specific applicable
approval policy.  Precedence (most specific wins):

1. Host policy   (``hosts.<ip>.approved_source_networks`` /
   ``approved_destination_networks`` of the *target* host)
2. Zone policy   (``zones.<name>.approved_source_networks`` / ``..._destination_...``)
3. Global policy (``global_policy.approved_source_networks`` / ``..._destination_...``)

If two equally specific policies could apply and disagree (e.g. the target
IP falls in two zones whose most-specific prefixes tie), the result is
"Ambiguous Policy" and the rule requires manual review.  Absence of any
policy is reported as "No Policy Defined" — a warning, not a rejection,
unless strict mode requires explicit approval.

Approved entries are matched exactly as declared: a ``/32`` (or ``/128``)
is never widened, and the rule's own scope is never replaced by a broader
zone — the policy only classifies, it does not rewrite.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from .config import AnalyzerConfig

LOG = logging.getLogger(__name__)

STATUS_APPROVED = "Approved"
STATUS_OUTSIDE = "Outside Approved Scope"
STATUS_NO_POLICY = "No Policy Defined"
STATUS_AMBIGUOUS = "Ambiguous Policy"
STATUS_REVIEW = "Manual Review Required"


@dataclass
class ScopeEvaluation:
    source_status: str = STATUS_NO_POLICY
    destination_status: str = STATUS_NO_POLICY
    matched_source_policy: str = ""
    matched_destination_policy: str = ""
    violation: bool = False
    notes: List[str] = field(default_factory=list)

    @property
    def needs_review(self) -> bool:
        return STATUS_AMBIGUOUS in (self.source_status, self.destination_status)


def _parse_value(value: str):
    """Parse an IP or CIDR into a network object; None if unparsable."""
    value = str(value).strip()
    if not value:
        return None
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def _within(value_net, approved: List[str]) -> Tuple[bool, str]:
    """Is value entirely inside any approved network? -> (yes, matching entry)."""
    for entry in approved:
        net = _parse_value(entry)
        if net is None or net.version != value_net.version:
            continue
        if value_net.subnet_of(net):
            return True, entry
    return False, ""


def _zone_policy_lookup(
    config: AnalyzerConfig, target_ip: str, key: str
) -> Tuple[Optional[List[str]], str, bool]:
    """Zone-level approved networks for the rule's target host.

    Zone policies express what hosts *in that zone* may communicate with:
    ``approved_source_networks`` = who may reach them, and
    ``approved_destination_networks`` = where they may send.  The applicable
    zone is therefore the zone the TARGET host belongs to.  Returns
    (approved list or None, policy label, ambiguous?); ambiguous is True
    when two zones tie at the same most-specific prefix length with
    different approval lists.
    """
    value_net = _parse_value(target_ip)
    if value_net is None:
        return None, "", False
    matches: List[Tuple[int, str, List[str]]] = []  # (prefixlen, zone, approved)
    for zone, pol in config.zone_policies.items():
        if key not in pol:
            continue
        best_prefix = -1
        for cidr in config.zones.get(zone, []):
            net = _parse_value(cidr)
            if net is None or net.version != value_net.version:
                continue
            if value_net.subnet_of(net):
                best_prefix = max(best_prefix, net.prefixlen)
        if best_prefix >= 0:
            matches.append((best_prefix, zone, pol[key]))
    if not matches:
        return None, "", False
    matches.sort(key=lambda m: -m[0])
    top_prefix = matches[0][0]
    top = [m for m in matches if m[0] == top_prefix]
    if len(top) > 1 and any(sorted(m[2]) != sorted(top[0][2]) for m in top[1:]):
        zones = ", ".join(sorted(m[1] for m in top))
        return None, f"zones {zones} (conflicting)", True
    _, zone, approved = top[0]
    return approved, f"zone '{zone}' {key}", False


def _resolve_policy(
    config: AnalyzerConfig,
    target_ip: str,
    checked_value: str,
    key: str,
) -> Tuple[str, str, List[str]]:
    """Most specific applicable policy for one direction.

    Returns (status, matched policy label, notes).  Host policy is read from
    the *target* host's configuration; zone policy from the zone the checked
    endpoint belongs to; global policy last.
    """
    notes: List[str] = []
    value_net = _parse_value(checked_value)
    if value_net is None:
        return STATUS_REVIEW, "", [f"Cannot parse {checked_value!r} for policy evaluation"]

    # A host's own lists govern its *peers*: approved_source_networks = who
    # may reach it, approved_destination_networks = where it may send.  When
    # the checked endpoint is the target host itself (the destination of an
    # inbound rule, or the source of an outbound rule), the host-level check
    # is skipped and evaluation falls through to zone/global policy.
    checked_is_self = str(checked_value).split("/")[0] == target_ip
    host_cfg = config.host_cfg(target_ip)
    if host_cfg is not None and not checked_is_self:
        approved = getattr(host_cfg, key, [])
        if approved:
            ok, entry = _within(value_net, approved)
            label = f"hosts.{target_ip}.{key}"
            if ok:
                return STATUS_APPROVED, f"{label} ({entry})", notes
            return STATUS_OUTSIDE, label, notes

    approved, label, ambiguous = _zone_policy_lookup(config, target_ip, key)
    if ambiguous:
        return STATUS_AMBIGUOUS, label, [
            "Equally specific zone policies conflict; approve explicitly at "
            "host level or reconcile the zone definitions"
        ]
    if approved is not None and not checked_is_self:
        ok, entry = _within(value_net, approved)
        if ok:
            return STATUS_APPROVED, f"{label} ({entry})", notes
        return STATUS_OUTSIDE, label, notes

    approved = config.global_policy.get(key)
    if approved and not checked_is_self:
        ok, entry = _within(value_net, approved)
        if ok:
            return STATUS_APPROVED, f"global_policy.{key} ({entry})", notes
        return STATUS_OUTSIDE, f"global_policy.{key}", notes

    return STATUS_NO_POLICY, "", notes


def evaluate_rule_scope(
    config: AnalyzerConfig,
    target_ip: str,
    source_value: str,
    destination_value: str,
) -> ScopeEvaluation:
    """Evaluate a candidate rule's source and destination against policy.

    ``target_ip`` is the host whose configuration supplies host-level policy
    (the destination for inbound rules, the source for outbound rules).
    Multiple comma-separated source values are each checked; the worst
    outcome wins.
    """
    ev = ScopeEvaluation()

    order = [STATUS_APPROVED, STATUS_NO_POLICY, STATUS_OUTSIDE, STATUS_AMBIGUOUS, STATUS_REVIEW]
    results = []
    for part in [p.strip() for p in str(source_value).split(",") if p.strip()]:
        status, label, notes = _resolve_policy(
            config, target_ip, part, "approved_source_networks"
        )
        ev.notes.extend(notes)
        results.append((order.index(status), status, label))
    if results:
        # The worst outcome across comma-separated source parts wins.
        _, worst, matched = max(results, key=lambda r: r[0])
        if not matched:
            matched = next((r[2] for r in results if r[2]), "")
        ev.source_status, ev.matched_source_policy = worst, matched

    status, label, notes = _resolve_policy(
        config, target_ip, destination_value, "approved_destination_networks"
    )
    ev.notes.extend(notes)
    ev.destination_status, ev.matched_destination_policy = status, label

    if STATUS_OUTSIDE in (ev.source_status, ev.destination_status):
        ev.violation = True
        ev.notes.append("Rule scope is outside the approved networks of the matched policy")
    if ev.source_status == STATUS_NO_POLICY and ev.destination_status == STATUS_NO_POLICY:
        ev.notes.append("No approved-network policy applies to this rule")
    return ev
