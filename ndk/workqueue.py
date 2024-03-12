#
# Copyright (C) 2016 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""Defines WorkQueue for delegating asynchronous work to subprocesses."""
from __future__ import annotations

import collections
import logging
import multiprocessing
import multiprocessing.managers
import os
import signal
import sys
import traceback
from abc import ABC, abstractmethod
from collections.abc import Hashable
from queue import Queue
from types import FrameType
from typing import (
    Any,
    Callable,
    Concatenate,
    Deque,
    Dict,
    Generic,
    Iterable,
    List,
    Optional,
    ParamSpec,
    TypeVar,
    Union,
)

IS_WINDOWS = sys.platform == "win32"


if IS_WINDOWS:
    import ctypes.wintypes

    ProcessGroup = Optional[ctypes.wintypes.HANDLE]


def logger() -> logging.Logger:
    """Returns the module level logger."""
    return logging.getLogger(__name__)


def worker_sigterm_handler(_signum: int, _frame: Optional[FrameType]) -> None:
    """Raises SystemExit so atexit/finally handlers can be executed."""
    sys.exit()


class TaskError(Exception):
    """An error for an exception raised in a worker process.

    Exceptions raised in the worker will not be printed by default, and will
    also not halt execution. We catch these exceptions in the worker process
    and pass them through the queue. Results are checked, and if the result is
    a TaskError the TaskError is raised in the caller's process. The message
    for the TaskError is the stack trace of the original exception, and will be
    printed if the TaskError is not caught.
    """


def create_windows_process_group() -> ProcessGroup:
    """Creates a Windows process group for this process."""
    import ndk.win32  # pylint: disable=import-outside-toplevel

    job = ndk.win32.CreateJobObject()

    limit_info = ndk.win32.JOBOBJECT_EXTENDED_LIMIT_INFORMATION(
        BasicLimitInformation=ndk.win32.JOBOBJECT_BASIC_LIMIT_INFORMATION(
            LimitFlags=ndk.win32.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        )
    )

    ndk.win32.SetInformationJobObject(
        job, ndk.win32.JobObjectExtendedLimitInformation, limit_info
    )
    ndk.win32.AssignProcessToJobObject(job, ndk.win32.GetCurrentProcess())
    return job


def assign_self_to_new_process_group() -> ProcessGroup:
    """Assigns this process to a new process group."""
    if sys.platform == "win32":
        return create_windows_process_group()
    os.setpgrp()
    return None


def kill_process_group(group: ProcessGroup) -> None:
    """Kills the process group."""
    if sys.platform == "win32":
        import ndk.win32  # pylint: disable=import-outside-toplevel

        ndk.win32.CloseHandle(group)
    else:
        os.kill(0, signal.SIGTERM)


class Worker:
    """A workqueue task executor."""

    IDLE_STATUS = "IDLE"
    EXCEPTION_STATUS = "EXCEPTION"

    def __init__(
        self,
        data: Any,
        task_queue: Queue[Task],
        result_queue: Queue[Any],
        manager: multiprocessing.managers.SyncManager,
    ) -> None:
        """Creates a Worker object.

        Args:
            task_queue: A multiprocessing.Queue of Tasks to retrieve work from.
            result_queue: A multiprocessing.Queue to push results to.
        """
        self.data = data
        self.task_queue = task_queue
        self.result_queue = result_queue
        # For multiprocess.Manager.Value, the type is actually ignored.
        # https://stackoverflow.com/a/21290961/632035
        self._status = manager.Value("", self.IDLE_STATUS)
        self._status_lock = manager.Lock()
        self.process = multiprocessing.Process(target=self.main)

    @property
    def status(self) -> str:
        """The worker's current status."""
        with self._status_lock:
            # Typeshed has a seemingly incorrect definition of
            # SyncManager.Value that just returns the wrapped type rather than
            # the proxy type.
            return self._status.value

    @status.setter
    def status(self, value: str) -> None:
        """Sets the status for the worker."""
        with self._status_lock:
            # Typeshed has a seemingly incorrect definition of
            # SyncManager.Value that just returns the wrapped type rather than
            # the proxy type.
            self._status.value = value

    def put_result(self, result: Any, status: str) -> None:
        """Puts a result onto the result queue."""
        with self._status_lock:
            # Typeshed has a seemingly incorrect definition of
            # SyncManager.Value that just returns the wrapped type rather than
            # the proxy type.
            self._status.value = status
        self.result_queue.put(result)

    @property
    def pid(self) -> Optional[int]:
        """The PID of the worker process."""
        return self.process.pid

    def is_alive(self) -> bool:
        """True if the worker process is currently alive."""
        return self.process.is_alive()

    def start(self) -> None:
        """Starts the worker process."""
        self.process.start()

    def terminate(self) -> None:
        """Terminates the worker process."""
        self.process.terminate()

    def join(self, timeout: Optional[float] = None) -> None:
        """Joins the worker process."""
        self.process.join(timeout)

    def main(self) -> None:
        """Main loop for worker processes."""
        group = assign_self_to_new_process_group()
        signal.signal(signal.SIGTERM, worker_sigterm_handler)
        try:
            while True:
                logger().debug("worker %d waiting for work", os.getpid())
                task = self.task_queue.get()
                logger().debug("worker %d running task", os.getpid())
                result = task.run(self)
                logger().debug("worker %d putting result", os.getpid())
                self.put_result(result, self.IDLE_STATUS)
        except SystemExit:
            pass
        except:  # pylint: disable=bare-except
            logger().debug("worker %d raised exception", os.getpid())
            trace = "".join(traceback.format_exception(*sys.exc_info()))
            self.put_result(TaskError(trace), self.EXCEPTION_STATUS)
        finally:
            # multiprocessing.Process.terminate() doesn't kill our descendents.
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            logger().debug("worker %d killing process group", os.getpid())
            kill_process_group(group)
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
        logger().debug("worker %d exiting", os.getpid())


ResultT = TypeVar("ResultT")
ParamT = ParamSpec("ParamT")


class Task:
    """A task to be executed by a worker process."""

    def __init__(
        self,
        func: Callable[Concatenate[Worker, ParamT], ResultT],
        *args: ParamT.args,
        **kwargs: ParamT.kwargs,
    ) -> None:
        """Creates a task.

        Args:
            func: An invocable object to be executed by a worker process.
            args: Arguments to be passed to the task.
            kwargs: Keyword arguments to be passed to the task.
        """
        self.func = func
        self.args = args
        self.kwargs = kwargs

    def run(self, worker_data: Any) -> Any:
        """Invokes the task."""
        return self.func(worker_data, *self.args, **self.kwargs)


class ProcessPoolWorkQueue:
    """A pool of processes for executing work asynchronously."""

    join_timeout = 8  # Timeout for join before trying SIGKILL.

    def __init__(
        self,
        num_workers: int = multiprocessing.cpu_count(),
        task_queue: Optional[Queue[Task]] = None,
        result_queue: Optional[Queue[Any]] = None,
        worker_data: Optional[Any] = None,
    ) -> None:
        """Creates a WorkQueue.

        Worker threads are spawned immediately and remain live until both
        terminate() and join() are called.

        Args:
            num_workers: Number of worker processes to spawn.
            task_queue: multiprocessing.Queue for tasks. Allows multiple work
                queues to share a single task queue. If None, the work queue
                creates its own.
            result_queue: multiprocessing.Queue for results. Allows multiple
                work queues to share a single result queue. If None, the work
                queue creates its own.
            worker_data: Data to be passed to every task run by this work
                queue.
        """
        self.manager = multiprocessing.Manager()

        if task_queue is None:
            self.task_queue = self.manager.Queue()
            self.owns_task_queue = True
        else:
            self.task_queue = task_queue
            self.owns_task_queue = False

        if result_queue is None:
            self.result_queue = self.manager.Queue()
            self.owns_result_queue = True
        else:
            self.result_queue = result_queue
            self.owns_result_queue = False

        self.worker_data = worker_data

        self.workers: List[Worker] = []
        # multiprocessing.JoinableQueue's join isn't able to implement
        # finished() because it doesn't come in a non-blocking flavor.
        self.num_tasks = 0
        self._spawn_workers(num_workers)

    def add_task(
        self,
        func: Callable[Concatenate[Worker, ParamT], ResultT],
        *args: ParamT.args,
        **kwargs: ParamT.kwargs,
    ) -> None:
        """Queues up a new task for execution.

        Tasks are executed in order of insertion as worker processes become
        available.

        Args:
            func: An invocable object to be executed by a worker process.
            args: Arguments to be passed to the task.
            kwargs: Keyword arguments to be passed to the task.
        """
        self.task_queue.put(Task(func, *args, **kwargs))
        self.num_tasks += 1

    def get_result(self) -> Any:
        """Gets a result from the queue, blocking until one is available."""
        result = self.result_queue.get()
        if isinstance(result, TaskError):
            raise result
        self.num_tasks -= 1
        return result

    @property
    def has_pending_results(self) -> bool:
        return not self.result_queue.empty()

    # TODO: Make ProcessPoolWorkQueue a descendant of BaseWorkQueue and dedup.
    # We can't trivially make this change because ProcessPoolWorkQueue isn't currently
    # type safe for its task result, and a single instance may be used for multiple
    # result types.
    def get_results(self) -> list[ResultT]:
        """Gets all pending results.

        If no results are available, this will block until at least one is
        available. It will then continue dequeing until the queue is empty, and
        then return.
        """
        results: list[ResultT] = []
        results.append(self.get_result())
        while self.has_pending_results:
            results.append(self.get_result())
        return results

    def terminate(self) -> None:
        """Terminates all worker processes."""
        for worker in self.workers:
            logger().debug("terminating %d", worker.pid)
            worker.terminate()

    def join(self) -> None:
        """Waits for all worker processes to exit."""
        for worker in self.workers:
            logger().debug("joining %d", worker.pid)
            worker.join(self.join_timeout)
            if worker.is_alive():
                logger().error("worker %d will not die; sending SIGKILL", worker.pid)
                if worker.pid is not None:
                    os.killpg(worker.pid, signal.SIGKILL)
                worker.join()
        self.workers = []

    def finished(self) -> bool:
        """Returns True if all tasks have completed execution."""
        return self.num_tasks == 0

    def _spawn_workers(self, num_workers: int) -> None:
        """Spawns the worker processes.

        Args:
            num_workers: Number of worker proceeses to spawn.
        """
        for _ in range(num_workers):
            worker = Worker(
                self.worker_data, self.task_queue, self.result_queue, self.manager
            )
            worker.start()
            self.workers.append(worker)


class BasicWorker:
    """A worker for a BasicWorkQueue."""

    def __init__(self, data: Any) -> None:
        self.data = data


class BaseWorkQueue(ABC, Generic[ResultT]):
    @abstractmethod
    def get_result(self) -> ResultT: ...

    @property
    @abstractmethod
    def has_pending_results(self) -> bool: ...

    def get_results(self) -> list[ResultT]:
        """Gets all pending results.

        If no results are available, this will block until at least one is
        available. It will then continue dequeing until the queue is empty, and
        then return.
        """
        results: list[ResultT] = []
        results.append(self.get_result())
        while self.has_pending_results:
            results.append(self.get_result())
        return results


class BasicWorkQueue(BaseWorkQueue[ResultT]):
    """A WorkQueue that does not delegate.

    This is the simplest possible implementation of a workqueue, performing all
    the work on the same thread. Useful for debugging when trying to determine
    if an issue is being caused by synchronization or IPC issues.
    """

    # pylint: disable=unused-argument
    def __init__(
        self,
        num_workers: Optional[int] = None,
        task_queue: Optional[Queue[Task]] = None,
        result_queue: Optional[Queue[ResultT]] = None,
        worker_data: Optional[Any] = None,
    ) -> None:
        """Creates a SerialWorkQueue."""
        self.task_queue: Deque[Task] = collections.deque()
        self.worker_data = worker_data

    # pylint: enable=unused-argument

    def add_task(
        self,
        func: Callable[Concatenate[Worker, ParamT], ResultT],
        *args: ParamT.args,
        **kwargs: ParamT.kwargs,
    ) -> None:
        """Queues up a new task for execution.

        Tasks are executed when get_result is called.

        Args:
            func: An invocable object to be executed by a worker process.
            args: Arguments to be passed to the task.
            kwargs: Keyword arguments to be passed to the task.
        """
        self.task_queue.append(Task(func, *args, **kwargs))

    def get_result(self) -> Any:
        """Executes a task and returns the result."""
        task = self.task_queue.popleft()
        try:
            return task.run(BasicWorker(self.worker_data))
        except Exception as ex:
            trace = "".join(traceback.format_exception(*sys.exc_info()))
            raise TaskError(trace) from ex

    def terminate(self) -> None:
        """Does nothing."""

    def join(self) -> None:
        """Does nothing."""

    @property
    def num_tasks(self) -> int:
        """Number of tasks that have not yet been claimed."""
        return len(self.task_queue)

    @property
    def has_pending_results(self) -> bool:
        return False

    @property
    def workers(self) -> List[Worker]:
        """List of workers."""
        return []

    def finished(self) -> bool:
        """Returns True if all tasks have completed execution."""
        return self.num_tasks == 0


ShardT = TypeVar("ShardT")


class ShardingGroup(Hashable, Generic[ShardT]):
    @property
    def shards(self) -> list[ShardT]:
        raise NotImplementedError


class ShardingWorkQueue(BaseWorkQueue[ResultT], Generic[ResultT, ShardT]):
    def __init__(
        self, device_groups: Iterable[ShardingGroup[ShardT]], procs_per_device: int
    ) -> None:
        self.manager = multiprocessing.Manager()
        self.result_queue = self.manager.Queue()
        self.task_queues: Dict[ShardingGroup[ShardT], Queue[Task]] = {}

        self.work_queues: Dict[ShardingGroup[ShardT], Dict[Any, WorkQueue]] = {}
        self.num_tasks = 0
        for group in device_groups:
            self.work_queues[group] = {}
            self.task_queues[group] = self.manager.Queue()
            for shard in group.shards:
                self.work_queues[group][shard] = WorkQueue(
                    procs_per_device,
                    task_queue=self.task_queues[group],
                    result_queue=self.result_queue,
                    worker_data=[shard],
                )

    def add_task(
        self,
        group: ShardingGroup[ShardT],
        func: Callable[Concatenate[Worker, ParamT], ResultT],
        *args: ParamT.args,
        **kwargs: ParamT.kwargs,
    ) -> None:
        self.task_queues[group].put(Task(func, *args, **kwargs))
        self.num_tasks += 1

    def get_result(self) -> Any:
        """Gets a result from the queue, blocking until one is available."""
        result = self.result_queue.get()
        if isinstance(result, TaskError):
            raise result
        self.num_tasks -= 1
        return result

    def terminate(self) -> None:
        for group_queues in self.work_queues.values():
            for work_queue in group_queues.values():
                work_queue.terminate()

    def join(self) -> None:
        for group_queues in self.work_queues.values():
            for work_queue in group_queues.values():
                work_queue.join()

    @property
    def has_pending_results(self) -> bool:
        return not self.result_queue.empty()

    def finished(self) -> bool:
        """Returns True if all tasks have completed execution."""
        return self.num_tasks == 0


WorkQueue = ProcessPoolWorkQueue
AnyWorkQueue = Union[BasicWorkQueue[Any], ProcessPoolWorkQueue]
