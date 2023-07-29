# Linux-Ipdump
一个简单的数据包捕获与分析程序，含QT可视化界面
# 程序可能含有部分bug,读者可以自行在源代码基础上修改完善！
# 程序内容可能含有部分作者的个人信息，自用的情况注意可以删除或者修改为自己的信息！！！

(1)编译源文件

![image](https://github.com/neuljh/Linux-Ipdump/assets/132900799/5618f603-a050-4d55-93ae-24392a17bde8)

(2)查看帮助信息

![image](https://github.com/neuljh/Linux-Ipdump/assets/132900799/cbd55332-3219-4e4d-a411-bd78ccea7d8b)

(3)默认规则捕获数据包

![image](https://github.com/neuljh/Linux-Ipdump/assets/132900799/3a75185d-c161-41aa-8835-afb618dee49c)

由于默认数据包大多数都是IP和TCP数据包，因此后面不对IP和TCP进行专门的过滤实验。

(4)捕获全部的数据包

![image](https://github.com/neuljh/Linux-Ipdump/assets/132900799/5c160421-1256-4f1e-bec8-65db123e048c)

(5)捕获ARP数据包并显示Ethernet头部和DUMP

![image](https://github.com/neuljh/Linux-Ipdump/assets/132900799/be212d80-91e7-4e6e-bc06-a186cb4afdb4)

(6)捕获ICMP数据包
在实验测试中，我发现捕获的数据包基本上没有ICMP和UDP包，因此这里我们采用另一台主机和本主机通信的方式来捕获对应的ICMP数据包。参考下图逻辑：

![image](https://github.com/neuljh/Linux-Ipdump/assets/132900799/2264e0c4-1948-462d-bc02-7c5886849fb4)

首先服务端(本主机)输入以下命令，循环捕获ICMP数据包：

![image](https://github.com/neuljh/Linux-Ipdump/assets/132900799/801a4e40-6948-49e2-8d3c-9e3edb4d55a1)

客户端主机打开终端，向服务端主机(IP地址为192.168.176.132)发送20个ICMP数据包：

![image](https://github.com/neuljh/Linux-Ipdump/assets/132900799/1bccdc0f-d426-4023-8478-c3b59466db05)

展示部分捕获数据包：

![image](https://github.com/neuljh/Linux-Ipdump/assets/132900799/56c55307-7895-4a5e-b5e0-f583a592f8de)

(7)捕获UDP数据包
在实验测试中，我发现捕获的数据包基本上没有ICMP和UDP包，因此这里我们采用另一台主机和本主机通信的方式来捕获对应的UDP数据包。参考下图逻辑：

![image](https://github.com/neuljh/Linux-Ipdump/assets/132900799/7242c264-2f41-46d1-be4e-1f907cd85d48)

首先建立两个主机的UDP通信。
服务端(IP地址为192.168.176.132)输入以下命令：

![image](https://github.com/neuljh/Linux-Ipdump/assets/132900799/c805f953-21e9-4ff3-8159-4c882c499247)

客户端输入以下命令：

![image](https://github.com/neuljh/Linux-Ipdump/assets/132900799/cede884b-52b4-427d-ac29-5897c7f2e96b)

服务端循环监听捕获UDP数据包：

![image](https://github.com/neuljh/Linux-Ipdump/assets/132900799/ec0f5726-90fa-4712-acf1-b423bed04159)

服务端发送消息1，客户端回复消息2：

![image](https://github.com/neuljh/Linux-Ipdump/assets/132900799/3b4ed02b-9dae-470b-b95c-069dc00c6741)

展示部分捕获UDP数据包：

![image](https://github.com/neuljh/Linux-Ipdump/assets/132900799/29b40c15-d765-4e19-8765-f2988f6847b3)


(8)显示统计信息
为了方便,这里直接查看(7)中的数据包统计信息：

![image](https://github.com/neuljh/Linux-Ipdump/assets/132900799/0c12af26-d9ab-44a6-bd3f-23f5d97aec70)

(9)选择指定IP地址和端口号

![image](https://github.com/neuljh/Linux-Ipdump/assets/132900799/5501e138-5529-46f2-99db-734035a5125a)


(10)发送畸形TCP数据包
在命令行指定该数据包的源IP地址、源端口号、目的IP地址和目的端口号。

![image](https://github.com/neuljh/Linux-Ipdump/assets/132900799/f58c6d0d-3af7-4716-a802-2a9425dfb7b7)

畸形TCP数据包发送成功。
