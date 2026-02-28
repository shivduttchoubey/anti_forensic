import json

from src.analyzers.network import NetworkAnalyzer, correlate_results
from src.analyzers.memory import MemoryAnalyzer


def run_analysis(pcap_path: str, mem_path: str) -> dict:
    """Convenience entry point combining network and memory analysis.

    Returns a composite structure that includes individual results plus
    correlation tags. This simulates what a unified scoring engine might
    consume.
    """
    network_result = NetworkAnalyzer().analyze(pcap_path)
    memory_result = MemoryAnalyzer().analyze(mem_path)
    correlation = correlate_results(network_result, memory_result)

    aggregate = {
        "network": network_result,
        "memory": memory_result,
        "correlation": correlation,
    }
    print(json.dumps(aggregate, indent=2))
    return aggregate


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print("Usage: python -m src.analyzers.main <pcap> <memory_dump>")
        sys.exit(1)

    run_analysis(sys.argv[1], sys.argv[2])
