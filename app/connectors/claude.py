from .mock import MockConnector


class ClaudeConnector(MockConnector):
    """Claude 连接器"""
    
    def __init__(self):
        super().__init__("claude", "us")
