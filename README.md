# Python-WebSocket
基于Python3的WebSocket服务器
A WebSocket server based on Python3

## 使用方式 / Usage
```python
    import time
    import threading
    import WebSocket
    
    # 初始化WebSocket / Initialize WebSocket
    ws = WebSocket.WebSocketServer('localhost', 8080)
    
    # 绑定消息回调
    ws.add_callback(lambda clint, msg: print(clint, msg))
    
    try:
        # 开启服务 / Start Server
        t = threading.Thread(target=ws.run_forever)
        t.start()
        
        # 10秒内初始化js的demo代码😏 / You got 10 seconds to run js demo
        time.sleep(10)
        # 给所有客户端发送消息 / Send message to all clients
        for name, client in ws.get_clients().items():
            client.send('Hello World!')
        
        t.join()
    finally:
        # 关闭服务 / Shutdown Server
        ws.close()
```
```javascript
    const ws = new WebSocket('ws://localhost:8080');
    ws.onmessage = (msg) => console.log(msg);
```
