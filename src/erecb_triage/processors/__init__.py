from erecb_triage.processors.base import Processor, ProcessorError, ProcessorResult

__all__ = [
    "ArchiveUnarchiver", "ArtifactInventory", "FileRetriever", "GHIntel", "IPRetriever", "InputStager", "YaraScan", "Processor",
    "ProcessorError", "ProcessorResult",
]


def __getattr__(name: str):
    """Load concrete adapters only when requested, avoiding repository import cycles."""
    if name == "ArchiveUnarchiver":
        from erecb_triage.processors.archive_unarchiver import ArchiveUnarchiver
        return ArchiveUnarchiver
    if name == "ArtifactInventory":
        from erecb_triage.processors.artifact_inventory import ArtifactInventory
        return ArtifactInventory
    if name == "FileRetriever":
        from erecb_triage.processors.file_retriever import FileRetriever
        return FileRetriever
    if name == "InputStager":
        from erecb_triage.processors.input_stager import InputStager
        return InputStager
    if name == "GHIntel":
        from erecb_triage.processors.ghintel import GHIntel
        return GHIntel
    if name == "IPRetriever":
        from erecb_triage.processors.ip_retriever import IPRetriever
        return IPRetriever
    if name == "YaraScan":
        from erecb_triage.processors.yara_scan import YaraScan
        return YaraScan
    raise AttributeError(name)
