"""Linux process VMA string artifacts, selected by investigator PID."""

from volatility3.framework import renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.tor_session_trace import core
from volatility3.plugins.linux import pslist


class TorSessionTraceLinux(plugins.PluginInterface):
    """Find URL/onion strings in selected Linux process VMAs; no visit claim."""

    _required_framework_version = (2, 13, 0)
    _version = (0, 1, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Linux kernel", architectures=["Intel32", "Intel64"]
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(4, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid", element_type=int, description="PIDs selected after process review"
            ),
            requirements.IntRequirement(
                name="max_hits", description="Maximum hits per process", default=1000, optional=True
            ),
        ]

    def _generator(self):
        pids = self.config["pid"]
        if not pids:
            raise ValueError("At least one --pid is required")
        max_hits = self.config.get("max_hits", 1000)
        if max_hits < 1:
            raise ValueError("--max-hits must be positive")
        requested = set(pids)
        found = set()
        tasks = pslist.PsList.list_tasks(
            self.context,
            self.config["kernel"],
            filter_func=pslist.PsList.create_pid_filter(pids),
        )
        for task in tasks:
            pid = int(task.tgid)
            found.add(pid)
            name = utility.array_to_string(task.comm)
            if not task.mm:
                raise RuntimeError(f"PID {pid}: no user process memory map")
            layer_name = task.add_process_layer()
            if not layer_name:
                raise RuntimeError(f"PID {pid}: process layer unavailable")
            sections = list(task.get_process_memory_sections())
            if not sections:
                raise RuntimeError(f"PID {pid}: no process memory sections found")
            for hit in core.scan_layer(
                self.context.layers[layer_name], self.context, sections,
                self._progress_callback, max_hits,
            ):
                yield (0, (pid, name, format_hints.Hex(hit.offset),
                           hit.encoding, hit.kind, hit.artifact, "E1:process_memory_string"))
        if requested - found:
            raise RuntimeError(f"Selected PIDs not found: {sorted(requested - found)}")

    def run(self):
        return renderers.TreeGrid(
            [("PID", int), ("Process", str), ("Offset", format_hints.Hex),
             ("Encoding", str), ("Kind", str), ("Artifact", str), ("Evidence", str)],
            self._generator(),
        )
