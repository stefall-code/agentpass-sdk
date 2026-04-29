from .mock import MockConnector


class ErnieBotConnector(MockConnector):
    """ERNIE Bot 连接器"""
    
    def __init__(self):
        super().__init__("ernie", "cn")
