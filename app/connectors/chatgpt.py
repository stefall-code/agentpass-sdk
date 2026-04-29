from .mock import MockConnector


class ChatGPTConnector(MockConnector):
    """ChatGPT 连接器"""
    
    def __init__(self):
        super().__init__("chatgpt", "us")
