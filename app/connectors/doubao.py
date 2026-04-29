from .mock import MockConnector


class DoubaoConnector(MockConnector):
    """Doubao 连接器"""
    
    def __init__(self):
        super().__init__("doubao", "cn")
