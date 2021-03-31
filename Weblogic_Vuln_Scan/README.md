源工具链接：https://github.com/rabbitmask/WeblogicScan

# Weblogic_Vuln_Scan

简体中文 | [English](./README_EN.md)

截至 2021 年 3 月 29 日，weblogic 漏洞扫描工具。若存在未记录且已公开 POC 的漏洞，欢迎提交 issue。

原作者已经收集得比较完整了，在这里增加了新的漏洞检测，并修改了部分代码以增加可读性，修改了部分代码以提高准确率。

**注意**：部分漏洞由于稳定性原因需要多次测试才可验证

目前可检测漏洞编号有（部分非原理检测，需手动验证）：

+ weblogic administrator console
+ CVE-2014-4210
+ CVE-2016-0638
+ CVE-2016-3510
+ CVE-2017-3248
+ CVE-2017-3506
+ CVE-2017-10271
+ CVE-2018-2628
+ CVE-2018-2893
+ CVE-2018-2894
+ CVE-2018-3191
+ CVE-2018-3245
+ CVE-2018-3252
+ CVE-2019-2618
+ CVE-2019-2725
+ CVE-2019-2729
+ CVE-2019-2890
+ CVE-2020-2551
+ CVE-2020-2555
+ CVE-2020-2883
+ CVE-2020-14644
+ CVE-2020-14645
+ CVE-2020-14882                                                                                   
+ CVE-2020-14883
+ CVE-2020-14756
+ CVE-2020-14825

# 快速开始

### 依赖

+ python >= 3.6

进入项目目录，使用以下命令安装依赖库

```
$ pip3 install requests
```

### 使用说明

```
usage: ws.py [-h] -t TARGETS [TARGETS ...] -v VULNERABILITY
             [VULNERABILITY ...] [-o OUTPUT]

optional arguments:
  -h, --help            帮助信息
  -t TARGETS [TARGETS ...], --targets TARGETS [TARGETS ...]
                        直接填入目标或文件列表（默认使用端口7001）. 例子：
                        127.0.0.1:7001
  -v VULNERABILITY [VULNERABILITY ...], --vulnerability VULNERABILITY [VULNERABILITY ...]
                        漏洞名称或CVE编号，例子："weblogic administrator console"
  -o OUTPUT, --output OUTPUT
                        输出 json 结果的路径。默认不输出结果
```

# 结果样例

![image](https://user-images.githubusercontent.com/45038279/112823155-7f107080-90bb-11eb-9a84-db4134594f1d.png)

