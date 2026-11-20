"""One guarded input, followed by independent observation. Transport is trusted host code."""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Protocol

from .evidence import Refusal, digest
from .locators import Method, Surface, Target, resolve
from .models import Action, DistributionIdentity, Evidence, InterfaceMap, ObservationResult, Transition
from .screenshot import Box, Screenshot


@dataclass(frozen=True)
class LabAuthority:
    run_id: str
    media: DistributionIdentity
    source_commit: str
    snapshot_id: str
    synthetic_cow_only: bool
    physical_disk_attached: bool


@dataclass(frozen=True)
class Frame:
    png: bytes
    scale: float | None
    authority: LabAuthority
    surface: Surface
    passed_checks: frozenset[str]


class LabTransport(Protocol):
    def capture(self, deadline: float) -> Frame: ...

    def click_if_current(self, run_id: str, png_sha256: str, point: tuple[int, int],
                         deadline: float) -> None:
        """Atomically check run, authority and current framebuffer before one guest click."""
        ...


@dataclass(frozen=True)
class Grant:
    source: str
    destination: str
    target: Target


@dataclass(frozen=True)
class SafetyPolicy:
    map_sha256: str
    authority: LabAuthority
    grants: tuple[Grant, ...]
    change_region: Box
    methods: tuple[Method, ...] = tuple(Method)

    def authorize(self, mapping: InterfaceMap, edge: Transition, frame: Frame) -> Target:
        a = self.authority
        if (not a.run_id or not a.snapshot_id or not a.source_commit or a.source_commit != mapping.lab_commit
            or a.synthetic_cow_only is not True or a.physical_disk_attached is not False
            or a.media != mapping.identity or a != frame.authority
            or self.map_sha256 != digest(mapping.document)):
            raise Refusal("Missing disposable lab, ISO or session authorization")
        if (mapping.scale is None or not math.isfinite(mapping.scale) or mapping.scale <= 0
            or frame.scale != mapping.scale):
            raise Refusal("Unproven or divergent display scale")
        if not edge.verified or edge.source == mapping.terminal or edge.action is not Action.NEXT:
            raise Refusal("Only reviewed forward navigation from a nonterminal page is executable")
        grants = [g for g in self.grants if (g.source,g.destination)==(edge.source,edge.target)]
        if len(grants) != 1:
            raise Refusal("Missing or ambiguous transition authorization")
        target = grants[0].target
        if (target.label, target.role) != ("Next", "button"):
            raise Refusal("Only the Next button is authorized")
        state = next(s for s in mapping.states if s.id == edge.source)
        controls = [c for c in state.controls if c.label == target.label]
        if (len(controls) != 1 or controls[0].role != target.role or controls[0].box != target.box
            or edge.locator.box != target.box or edge.locator.point != target.point):
            raise Refusal("Map does not bind a unique authorized control")
        if not set(edge.before.requirements) <= frame.passed_checks:
            raise Refusal("Unproven preconditions")
        return target


class StateMachine:
    def __init__(self, mapping: InterfaceMap, policy: SafetyPolicy, transport: LabTransport,
                 recognize: Callable[[Screenshot], Iterable[str]], initial: str,
                 *, clock: Callable[[],float] = time.monotonic,
                 wait: Callable[[float],None] = time.sleep):
        if initial not in {s.id for s in mapping.states}:
            raise Refusal("Unknown initial state")
        self.mapping, self.policy, self.transport = mapping, policy, transport
        self.recognize, self.current = recognize, initial
        self.clock, self.wait = clock, wait
        self.halted = False
        self._consumed: set[str] = set()
        self._lock = threading.Lock()

    def step(self, edge_id: str) -> ObservationResult:
        with self._lock:
            return self._step(edge_id)

    def _step(self, edge_id: str) -> ObservationResult:
        start = self.clock()
        initial = self.current
        before = after = action = method = final = None
        errors = ()
        try:
            if self.halted:
                raise Refusal("Session has halted")
            edge = next((t for t in self.mapping.transitions if t.id == edge_id), None)
            if not edge or edge_id in self._consumed or initial != edge.source or initial == self.mapping.terminal:
                raise Refusal("Transition outside current state")
            deadline = start + edge.timeout
            def observe() -> tuple[Frame, Screenshot, Evidence]:
                f = self.transport.capture(deadline)
                shot = Screenshot.decode(f.png, self.mapping.resolution)
                matches = tuple(self.recognize(shot))
                if len(matches) > 1:
                    raise Refusal("Ambiguous screen")
                state = matches[0] if matches else None
                return f, shot, Evidence(state, shot.sha256, shot.image.size)

            frame, src, before = observe()
            final = before.state
            if final != initial:
                raise Refusal("Unexpected initial screen")
            target = self.policy.authorize(self.mapping, edge, frame)
            remaining = deadline - self.clock()
            if remaining <= 0:
                raise Refusal("Precondition timeout")
            method, point = resolve(src, frame.surface, target, self.policy.methods, remaining)
            previous_roi = src.roi(self.policy.change_region)
            if self.clock() >= deadline:
                raise Refusal("Locator timeout")
            self._consumed.add(edge_id)
            action = edge.action
            final = None
            self.transport.click_if_current(frame.authority.run_id, src.sha256, point, deadline)
            while self.clock() < deadline:
                fresh, shot, after = observe()
                final = after.state
                if frame.authority != fresh.authority or frame.scale != fresh.scale:
                    raise Refusal("Guest authority or scale changed")
                if final == edge.target:
                    if shot.roi(self.policy.change_region) == previous_roi:
                        raise Refusal("No visual change in transition region")
                    if not set(edge.after.requirements) <= fresh.passed_checks:
                        raise Refusal("Unproven postconditions")
                    if self.clock() >= deadline:
                        raise Refusal("Postcondition timeout")
                    self.current = final
                    break
                if final not in (None, initial):
                    raise Refusal("Unexpected posterior screen")
                self.wait(max(0, min(0.1, deadline - self.clock())))
            else:
                raise Refusal("Transition timeout")
        except Exception as exc:
            self.halted = True
            errors = (str(exc) or type(exc).__name__,)
        return ObservationResult(self.policy.authority.run_id, "live-observation",
            self.mapping.identity, self.mapping.installer, edge_id, initial, method, action,
            before, after, not errors, round((self.clock()-start)*1000), errors, final)
