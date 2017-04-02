#include <string>
#include <iostream>
#include <pcap.h>
using namespace std;

// 一个分组
class Packet {
public:
  // 原始数据
  string host;  // HTTP headers 中的 host 属性值
  string referer;  // HTTP headers 中 referer 属性值
  long sec;  // 分组被捕获的时间的秒位
  int uSec;  // 分组被捕获的时间的微秒位

  // 其他数据
  u_int numOfReqAfter;  // 该分组一秒内其他 HTTP 请求的个数

  // 构造函数
  Packet() { numOfReqAfter = 0; }

  // 析构函数
  ~Packet() {}
};

// 从 HTTP header 中根据传入的属性获取其属性值
string getAttr(string httpHeader, string attr, u_int maxLen) {
  size_t found = httpHeader.find(attr);
  string value = "";
  if (found != string::npos) {
    for (u_int i = found + attr.size(); i < maxLen; i++) {
      if (httpHeader[i] == '\n') {
        value = httpHeader.substr(found + attr.size(), i - found - attr.size());
        break;
      }
    }
  }
  return value;
}

int main() {
  // 具体代码的含义请参考
  // https://ferrets.me/liuren/article/网络流模式分析——入门
  string file = "seriesOperation.pcap";
  char errbuff[PCAP_ERRBUF_SIZE];
  pcap_t *pcap = pcap_open_offline(file.c_str(), errbuff);
  struct pcap_pkthdr *header;
  const u_char *data;

  // 创建分组的集合
  Packet *pcks = new Packet[4096];
  u_int pckCount = 0;

  // 循环对每一个包进行处理
  while (int returnValue = pcap_next_ex(pcap, &header, &data) >= 0) {
    u_int link = 14;  // 链路层头部的长度
    u_int network = (data[14] % 16) * 4;  // 网络层头部的长度
    // 链路、网络、传输层头部的总长度
    u_int end = (int)(data[link + network + 12] / 16 * 4) + network + link;
    // 分组的源端口
    int port = data[link + network] * 16 * 16 + data[link + network + 1];
    // 判断是否为 HTTP 请求包（有 HTTP 头部且端口不为 80）
    if (end != header->caplen && port != 80) {
      // 为分组设定时间
      pcks[pckCount].sec = header->ts.tv_sec;
      pcks[pckCount].uSec = header->ts.tv_usec;

      // 将非特殊字符压入字符串
      string httpHeader;
      for (u_int i = end; i < header->caplen; i++) {
        if ((data[i] >= 32 && data[i] <= 126) || data[i] == '\n')
          httpHeader.push_back(data[i]);
        else httpHeader.push_back('.');
      }
      httpHeader.push_back('\0');

      // 为分组设定 host 和 referer
      pcks[pckCount].host = getAttr(httpHeader, "\nHost: ", header->caplen);
      pcks[pckCount].host.pop_back();
      pcks[pckCount].referer = getAttr(httpHeader, "\nReferer: ", header->caplen);
      pcks[pckCount].referer.pop_back();

      // 计数器加 1
      pckCount++;
    }
  }

  // 计算每个分组一秒内 HTTP 请求的个数
  for (int i = 0; i < pckCount; i++) {
    for (int j = i; j < pckCount; j++) {
      double interval = (double)(pcks[j].sec - pcks[i].sec) +
                        (double)(pcks[j].uSec - pcks[i].uSec) * 0.000001;
      // 从前向后查找，若间隔时间小于 1 秒，则加 1
      if (interval < 1) pcks[i].numOfReqAfter++;
      else break;
    }
  }

  // 统计信息输出
  freopen("result.csv", "w", stdout);
  cout << "index, number of requests, referer match host, referer match referer, click" << endl;
  for (int i = 0; i < pckCount; i++) {
    // 输出序号和一秒内的请求个数
    cout << i << ", " << pcks[i].numOfReqAfter << ", ";
    // 输出这个分组的 referer 和上一个分组的 host 是否匹配
    if (i > 0 && pcks[i].referer != "" && pcks[i - 1].host != "" &&
        pcks[i].referer.find(pcks[i - 1].host) != string::npos)
      cout << "1, ";
    else cout << "0, ";
    // 输出这个分组的 host 和下一个分组的 host 是否匹配
    if (i + 1 < pckCount && pcks[i].referer != "" && pcks[i + 1].referer != "" &&
        pcks[i].referer == pcks[i + 1].referer)
      cout << "1, ";
    else cout << "0, ";
    // 换行
    cout << endl;
  }

  // 结束程序
  fclose(stdout);
  delete []pcks;
  return 0;
}
