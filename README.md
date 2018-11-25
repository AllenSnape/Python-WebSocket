# Python-WebSocket
基于Python3的WebSocket服务器
A WebSocket server based on Python3

## 使用方式 / Usage
```python
  ws = WebSocketServer('localhost', 8080)
  ws.run_forever()
```
```javascript
  const ws = new WebSocket('ws://localhost:8080');
  ws.onmessage = (msg) => console.log(msg);
```
