from .mock import MockConnector


class FeishuConnector(MockConnector):
    """Feishu 连接器"""
    
    def __init__(self):
        super().__init__("feishu", "cn")
