"""AutoPatch — autonomous vulnerability remediation agent."""

try:
    from importlib.metadata import version as _pkg_version

    __version__ = _pkg_version("autopatch")
except Exception:  # running from a source tree without installation
    __version__ = "0.2.0"
