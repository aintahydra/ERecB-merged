"""Domain exceptions and stable CLI exit codes."""


class YaraRulerError(Exception):
    exit_code = 70


class ConfigurationError(YaraRulerError):
    exit_code = 2


class RuleSyncError(YaraRulerError):
    exit_code = 3


class RuleBuildError(YaraRulerError):
    exit_code = 3


class CacheError(YaraRulerError):
    exit_code = 4


class ScanFileErrors(YaraRulerError):
    exit_code = 5


class ReportError(YaraRulerError):
    exit_code = 6
