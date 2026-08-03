import runpy
import tempfile
from pathlib import Path

from shadow_core.ingestion import AdapterContext, EvidenceSource

from nmap_flow_analyzer.ingestion import PcapAdapter, PcapngAdapter, SuricataEveAdapter


def test_generated_fixtures_are_deterministic_and_parseable() -> None:
    with tempfile.TemporaryDirectory() as directory:
        tmp_path = Path(directory)
        script = Path(__file__).parents[1] / "scripts" / "benchmark-ingestion.py"
        namespace = runpy.run_path(str(script))
        generators = (
            (namespace["eve"], SuricataEveAdapter),
            (namespace["pcap"], PcapAdapter),
            (namespace["pcapng"], PcapngAdapter),
        )
        for generator, adapter_type in generators:
            first = tmp_path / f"{adapter_type.__name__}-one"
            second = tmp_path / f"{adapter_type.__name__}-two"
            generator(first, 10)
            generator(second, 10)
            assert first.read_bytes() == second.read_bytes()
            assert len(list(adapter_type().records(EvidenceSource(first), AdapterContext()))) == 10
