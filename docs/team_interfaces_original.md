# 接口

## AES-128单块加密

aes内部函数的名字

```c++
class AES {
public:
    Bytes encryptBlock(
        const Key128& key,	//密钥长度
        const Block128& block	//分组长度
    );
};
```

## AES-CTR

反复调用AES-128：处理任意长度密文

```c++
class AES {
public:
    Bytes encryptCTR(
        const Key128& key,
        const Nonce& nonce,	//随机数
        const Bytes& plaintext
    );
};
```

## CMAC

1. 计算MAC

   message组织方式暂定：后续会加入其他（session id，sequence...）

   ```c++
   class CMAC {
   public:
       MacTag generate(
           const Key128& key,
           const Bytes& message
       );
   };
   ```

2. 验证MAC

   ```c++
   class CMAC {
   public:
       bool verify(
           const Key128& key,
           const Bytes& message,
           const MacTag& tag
       );
   };
   ```

3. 

## 网络传输

1. TCP通信

   ```c++
   class Network {
   public:
       //建立连接-客户端
       bool connect(
           const std::string& host,
           uint16_t port
       );
   
       //建立连接-服务端
       bool listen(
           uint16_t port
       );
       bool accept();
   
       //发送
       bool sendFrame(
           const Frame& frame
       );
   
       //接收
       bool receiveFrame(
           Frame& frame
       );
   
       //关闭
       void close();
   };
   ```

2. frame协议

   ```c++
   struct Frame {
       uint16_t type;
       SessionId sessionId;
       uint64_t sequence;
       Nonce nonce;
       Bytes payload;
       MacTag mac;
       
       // 将结构体struct转为字节，传输
       Bytes serialize(
       	const Frame& frame
   	);
   
       // 将收到的字节转为程序中的对象（struct）
   	Frame deserialize(
       	const Bytes& data
   	);
   };
   ```

   

3. 