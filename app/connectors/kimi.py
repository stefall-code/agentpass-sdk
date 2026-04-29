from .mock import MockConnector


class KimiConnector(MockConnector):
    """Kimi 连接器"""
    
    def __init__(self):
        super().__init__("kimi", "cn")
