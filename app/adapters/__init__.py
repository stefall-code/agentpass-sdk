try:
    from .agentpass_adapter import AgentPassAdapter, get_adapter, get_audit_adapter, AuditAdapter
except ImportError:
    AgentPassAdapter = None
    get_adapter = None

    class AuditAdapter:
        _instance = None
        _events = []

        @classmethod
        def get_instance(cls):
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

        def log_event(self, **kwargs):
            self._events.append(kwargs)

        def get_events(self, filters=None, limit=100):
            return self._events[-limit:]

        def get_all_events(self):
            return self._events.copy()

        def export_to_json(self, file_path=None):
            import json
            return json.dumps(self._events, indent=2, ensure_ascii=False)

        def export_to_csv(self, file_path=None):
            return ""

        def clear_events(self):
            self._events.clear()

        def get_event_count(self):
            return len(self._events)

    def get_audit_adapter():
        return AuditAdapter.get_instance()

__all__ = ["AgentPassAdapter", "get_adapter", "get_audit_adapter", "AuditAdapter"]
