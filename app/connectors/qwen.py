from .mock import MockConnector


class QwenConnector(MockConnector):
    """Qwen 连接器"""
    
    def __init__(self):
        super().__init__("qwen", "cn")
