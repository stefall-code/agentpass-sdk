from .mock import MockConnector


class GrokConnector(MockConnector):
    """Grok 连接器"""
    
    def __init__(self):
        super().__init__("grok", "us")
