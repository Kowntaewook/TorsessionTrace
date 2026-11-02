"""Windows process VAD string artifacts, selected by investigator PID."""

from volatility3.framework import renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.tor_session_trace import core
from volatility3.plugins.windows import pslist


class TorSessionTraceWindows(plugins.PluginInterface):
    """Find URL/onion strings in selected Windows process VADs; no visit claim."""

    _required_framework_version = (2, 0, 0)
    _version = (0, 1, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Windows kernel", architectures=["Intel32", "Intel64"]
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0)
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
        procs = pslist.PsList.list_processes(
            self.context,
            self.config["kernel"],
            filter_func=pslist.PsList.create_pid_filter(pids),
        )
        for proc in procs:
            pid = int(proc.UniqueProcessId)
            found.add(pid)
            name = utility.array_to_string(proc.ImageFileName)
            layer_name = proc.add_process_layer()
            if not layer_name:
                raise RuntimeError(f"PID {pid}: process layer unavailable")
            sections = [
                (int(vad.get_start()), int(vad.get_size()))
                for vad in proc.get_vad_root().traverse()
                if vad.get_size() > 0
            ]
            if not sections:
                raise RuntimeError(f"PID {pid}: no readable VADs found")
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
