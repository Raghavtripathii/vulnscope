class DetectorFindings(list):
    def __init__(self, items=(), status="ok"):
        super().__init__(items)
        self.status = status


def status_of(result) -> str:
    return getattr(result, "status", "ok")