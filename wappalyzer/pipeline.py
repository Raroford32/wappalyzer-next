import asyncio
import inspect
from dataclasses import dataclass
from typing import Dict, Sequence

from wappalyzer.models import (
    Protocol,
    ProtocolResult,
    RunStatus,
    worker_failure_protocol,
)
from wappalyzer.output import CanonicalProjector
from wappalyzer.runstore import EndpointClaim, RunStateError, RunStore


@dataclass(frozen=True)
class PipelineStats:
    endpoints_committed: int
    max_inflight_observed: int
    projected_records: int


def _worker_failure_results(endpoint):
    return tuple(worker_failure_protocol(endpoint, protocol) for protocol in Protocol)


def _normalize_results(endpoint, value):
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return _worker_failure_results(endpoint)
    results = tuple(value)
    if any(not isinstance(result, ProtocolResult) for result in results):
        return _worker_failure_results(endpoint)
    by_protocol = {result.protocol: result for result in results}
    if len(by_protocol) != len(results):
        return _worker_failure_results(endpoint)
    return tuple(
        by_protocol[protocol]
        if protocol in by_protocol
        else worker_failure_protocol(endpoint, protocol)
        for protocol in Protocol
    )


class BoundedScanPipeline:
    def __init__(
        self,
        *,
        store,
        scan_endpoint,
        projector,
        max_inflight,
        close_workers=None,
        projection_batch_records=256,
    ):
        if not isinstance(store, RunStore):
            raise TypeError("store must be a RunStore")
        if not callable(scan_endpoint):
            raise TypeError("scan_endpoint must be callable")
        if not isinstance(projector, CanonicalProjector):
            raise TypeError("projector must be a CanonicalProjector")
        if projector.store is not store:
            raise ValueError("projector and pipeline must use the same run store")
        if isinstance(max_inflight, bool) or not isinstance(max_inflight, int) or max_inflight < 1:
            raise ValueError("max_inflight must be a positive integer")
        if close_workers is not None and not callable(close_workers):
            raise TypeError("close_workers must be callable or None")
        if (
            isinstance(projection_batch_records, bool)
            or not isinstance(projection_batch_records, int)
            or projection_batch_records < 1
        ):
            raise ValueError("projection_batch_records must be a positive integer")

        self.store = store
        self.scan_endpoint = scan_endpoint
        self.projector = projector
        self.max_inflight = max_inflight
        self.close_workers = close_workers
        self.projection_batch_records = projection_batch_records
        self._active_scan_tasks = set()

    async def _close_workers(self):
        if self.close_workers is None:
            return
        result = self.close_workers()
        if inspect.isawaitable(result):
            await result

    async def _cancel_tasks(self, tasks):
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _execute(self):
        tasks: Dict[asyncio.Task, EndpointClaim] = {}
        endpoints_committed = 0
        max_inflight_observed = 0
        projected_records = 0
        records_since_projection = 0
        exhausted = False

        while tasks or not exhausted:
            while not exhausted and len(tasks) < self.max_inflight:
                claim = self.store.claim_endpoint()
                if claim is None:
                    exhausted = True
                    break
                task = asyncio.create_task(self.scan_endpoint(claim.endpoint))
                tasks[task] = claim
                self._active_scan_tasks.add(task)
                max_inflight_observed = max(max_inflight_observed, len(tasks))

            if not tasks:
                break

            done, _pending = await asyncio.wait(
                tuple(tasks),
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in sorted(done, key=lambda item: tasks[item].endpoint_id):
                claim = tasks.pop(task)
                self._active_scan_tasks.discard(task)
                try:
                    value = task.result()
                except asyncio.CancelledError:
                    raise
                except Exception:
                    results = _worker_failure_results(claim.endpoint)
                else:
                    results = _normalize_results(claim.endpoint, value)
                records_since_projection += self.store.commit_endpoint(claim, results)
                endpoints_committed += 1

            if records_since_projection >= self.projection_batch_records:
                projected_records += self.projector.project()
                records_since_projection = 0

        return PipelineStats(
            endpoints_committed=endpoints_committed,
            max_inflight_observed=max_inflight_observed,
            projected_records=projected_records,
        )

    async def run(self):
        status = self.store.status
        if status is RunStatus.INTERRUPTED:
            self.store.resume()
            status = self.store.status
        if status is RunStatus.READY:
            self.store.transition(RunStatus.EXECUTING)
            status = RunStatus.EXECUTING
        if status not in {
            RunStatus.EXECUTING,
            RunStatus.PROJECTING,
            RunStatus.PUBLISH_READY,
        }:
            raise RunStateError(f"pipeline cannot run while store is {status.value}")
        if status is RunStatus.PUBLISH_READY:
            return PipelineStats(0, 0, 0)

        tasks = set()
        try:
            if status is RunStatus.EXECUTING:
                execution_task = asyncio.create_task(self._execute())
                tasks.add(execution_task)
                stats = await execution_task
                tasks.clear()
                await self._close_workers()
                self.store.transition(RunStatus.PROJECTING)
            else:
                stats = PipelineStats(0, 0, 0)

            projected = self.projector.project()
            self.store.mark_workers_closed()
            self.store.reconcile_counts()
            self.store.transition(RunStatus.PUBLISH_READY)
            return PipelineStats(
                endpoints_committed=stats.endpoints_committed,
                max_inflight_observed=stats.max_inflight_observed,
                projected_records=stats.projected_records + projected,
            )
        except BaseException:
            await self._cancel_tasks((*tasks, *self._active_scan_tasks))
            self._active_scan_tasks.clear()
            try:
                await self._close_workers()
            except Exception:
                pass
            if self.store.status not in {
                RunStatus.INTERRUPTED,
                RunStatus.PUBLISH_READY,
                RunStatus.COMPLETE,
            }:
                self.store.interrupt()
            raise


__all__ = ["BoundedScanPipeline", "PipelineStats"]
