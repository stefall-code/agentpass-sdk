from .mock import MockConnector


class GeminiConnector(MockConnector):
    """Gemini 连接器"""
    
    def __init__(self):
        super().__init__("gemini", "us")
