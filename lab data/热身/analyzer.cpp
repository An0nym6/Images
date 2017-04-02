#include <string>
#include <iostream>
#include <pcap.h>
using namespace std;

// host 或者 referer
class Url {
public:
  string url;  // host 或者 referer 的 url
  int number;  // 该 host 或者 referer 出现的次数

  // 设置一个 host 或者一个 referer
  void set(string url_, int number_) {
    url = url_;
    number = number_;
  }
};

// 一个时间片（每秒）
class Slot {
public:
  // 原始数据
  int numOfReqs;  // HTTP 请求的个数
  Url *hosts;  // HTTP 中出现过的 hosts 以及它们的数量
  Url *referers;  // HTTP 中出现过的 referers 以及它们的数量
  int hostsSize;  // hosts 个数
  int referersSize;  // referers 个数

  // 其他数据
  bool isSameHost;  // 最高频 host 与上一秒是否相同
  bool isSameReferer;  // 最高频 referer 是否与上一秒相同

  Slot() {
    numOfReqs = 0;
    hosts = new Url[2048];
    referers = new Url[2048];
    hostsSize = 0;
    referersSize = 0;
  }

  ~Slot() {
    delete []hosts;
    delete []referers;
  }

  // 为该时间片添加一个 host
  void addHost(string newHost) {
    // 遍历数组加入新的 host
    int i;
    // 如果找到有同样的 host，将其计数器加 1
    for (i = 0; i < hostsSize; i++) {
      if (hosts[i].url == newHost) {
        hosts[i].number++;
        break;
      }
    }
    // 否则添加一个新的 host，设置计数器为 1
    if (i == hostsSize) {
      hosts[hostsSize].set(newHost, 1);
      hostsSize++;
    }
  }

  // 为该时间片添加一个 referer
  void addReferer(string newReferer) {
    // 遍历数组加入新的 host
    int i;
    // 如果找到有同样的 host，将其计数器加 1
    for (i = 0; i < referersSize; i++) {
      if (referers[i].url == newReferer) {
        referers[i].number++;
        break;
      }
    }
    // 否则添加一个新的 host，设置计数器为 1
    if (i == referersSize) {
      referers[referersSize].set(newReferer, 1);
      referersSize++;
    }
  }

  // 获取 HTTP headers 中 host 的最高频属性值
  string getHost() {
    // 找出最高频的 host
    int max = -1;
    string maxHost = "empty";
    for (int i = 0; i < hostsSize; i++) {
      if (hosts[0].number > max) {
        max = hosts[0].number;
        maxHost = hosts[0].url;
      }
    }
    // 返回 host
    return maxHost;
  }

  // 获取 HTTP 中出现过的 referers 以及它们的数量
  string getReferer() {
    // 找出最高频的 host
    int max = -1;
    string maxReferer = "empty";
    for (int i = 0; i < referersSize; i++) {
      if (referers[0].number > max) {
        max = referers[0].number;
        maxReferer = referers[0].url;
      }
    }
    // 返回 referer
    return maxReferer;
  }
};

int main() {
  // 具体代码的含义请参考
  // https://ferrets.me/liuren/article/网络流模式分析——入门
  string file = "seriesOperation.pcap";
  char errbuff[PCAP_ERRBUF_SIZE];
  pcap_t *pcap = pcap_open_offline(file.c_str(), errbuff);
  struct pcap_pkthdr *header;
  const u_char *data;
  u_int packetCount = 0;

  // 第一个包的时间
  long startSecond = -1;
  int startUSecond = -1;

  // 创建时间槽
  Slot *slots = new Slot[128];
  int maxSecond = 0;

  // 循环对每一个包进行处理
  while (int returnValue = pcap_next_ex(pcap, &header, &data) >= 0) {
    // 为第一个包的时间赋值
    if (startSecond == -1) {
      startSecond = header->ts.tv_sec;
      startUSecond = header->ts.tv_usec;
    }
    // 判断是否为 HTTP 请求包（有 HTTP 头部且端口不为 80）
    u_int link = 14;
    u_int network = (data[14] % 16) * 4;
    u_int end = (int)(data[link + network + 12] / 16 * 4) + network + link;
    int port = data[link + network] * 16 * 16 + data[link + network + 1];
    if (end != header->caplen && port != 80) {
      // 计算与第一个包的间隔时间
      double interval = (double)(header->ts.tv_sec - startSecond) +
                        (double)(header->ts.tv_usec - startUSecond) * 0.000001;
      int second = interval / 1;

      // 找到最后一个包的秒数
      if (second > maxSecond) maxSecond = second;

      // 将包的计数加 1
      slots[second].numOfReqs++;

      // 将每一个十六进制数压入字符串
      string httpHeader;
      for (u_int i = end; i < header->caplen; i++)
        httpHeader.push_back(data[i]);
      httpHeader.push_back('\0');

      // 寻找包的 host 并添加到对应的秒
      size_t found = httpHeader.find("\nHost: ");
      if (found != string::npos) {
        string newHost;
        for (u_int i = found + 7; i < header->caplen; i++) {
          if (httpHeader[i] == '\n') {
            newHost = httpHeader.substr(found + 7, i - found - 7);
            slots[second].addHost(newHost);
            break;
          }
        }
      }
      // 寻找包的 referer 并添加到对应的秒
      found = httpHeader.find("\nReferer: ");
      if (found != string::npos) {
        string newReferer;
        for (u_int i = found + 7; i < header->caplen; i++) {
          if (httpHeader[i] == '\n') {
            newReferer = httpHeader.substr(found + 10, i - found - 10);
            slots[second].addReferer(newReferer);
            break;
          }
        }
      }
    }
  }

  // 信息输出
  freopen("rawData.csv", "w", stdout);
  printf("index, number of requests, main host, main referer\n");
  for (int i = 0; i <= maxSecond; i++) {
    printf("%d, ", i);  // 输出秒数
    printf("%d, ", slots[i].numOfReqs);  // 输出该秒的请求数
    // 规范化 host 并输出
    string host = slots[i].getHost();
    for (int i = 0; i < host.size(); i++) {
      if (host[i] < 32 || host[i] > 126) {
        host.erase(host.begin() + i);
        i--;
      }
    }
    printf("%s, ", host.c_str());
    // 规范化 referer 并输出
    string referer = slots[i].getReferer();
    for (int i = 0; i < referer.size(); i++) {
      if (referer[i] < 32 || referer[i] > 126) {
        referer.erase(referer.begin() + i);
        i--;
      }
    }
    printf("%s\n", referer.c_str());
  }

  // 结束程序
  fclose(stdout);
  delete []slots;
  return 0;
}
