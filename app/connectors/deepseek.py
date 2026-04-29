from .mock import MockConnector


class DeepSeekConnector(MockConnector):
    """DeepSeek 连接器"""
    
    def __init__(self):
        super().__init__("deepseek", "cn")
