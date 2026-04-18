from __future__ import annotations

try:
    import win32event  # type: ignore
    import win32service  # type: ignore
    import win32serviceutil  # type: ignore
    import servicemanager  # type: ignore
except ImportError:  # pragma: no cover
    win32event = None
    win32service = None
    win32serviceutil = None
    servicemanager = None

from agent.main import WindowsEDRAgent


if win32serviceutil is not None:
    class SentinelAgentService(win32serviceutil.ServiceFramework):
        _svc_name_ = "SentinelAIWindowsAgent"
        _svc_display_name_ = "SentinelAI Windows Agent"
        _svc_description_ = "SentinelAI endpoint telemetry agent"

        def __init__(self, args: list[str]) -> None:
            super().__init__(args)
            self.stop_event = win32event.CreateEvent(None, 0, 0, None)
            self.agent = WindowsEDRAgent()

        def SvcStop(self) -> None:
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self.agent.stop()
            win32event.SetEvent(self.stop_event)

        def SvcDoRun(self) -> None:
            servicemanager.LogInfoMsg("SentinelAI Windows Agent service starting")
            self.agent.start()
            win32event.WaitForSingleObject(self.stop_event, win32event.INFINITE)


def main() -> None:
    if win32serviceutil is None:
        raise RuntimeError("pywin32 service modules are not installed")
    win32serviceutil.HandleCommandLine(SentinelAgentService)


if __name__ == "__main__":
    main()
