# Weblogic_alive

逻辑：

-s （scan模块）进行weblogic-ip+端口页面存活扫描,目标ip或域名保存在ip-scan.txt,支持c段(格式192.168.1.0/24),一行一个,执行python3 weblogic_alive.py -s即可。可访问页面保存在ip-scan-result.txt,如经T3协议确认weblogic站点则继续使用修改版weblogic—scaner,输出漏洞详情。（以下T3、IIOP模块可以单独跑，但T3模块已包含在scan模块，尽量只使用scan模块）

-t （T3模块）进行weblogic-T3协议扫描,目标ip或域名保存在ip-t3.txt,一行一个,执行python3 weblogic_alive.py -t即可。

-i （IIOP模块）进行weblogic-iiop协议扫描,目标ip或域名保存在ip-iiop.txt,一行一个,执行python3 weblogic_alive.py -i即可。

文件：

poc5.ser：用于T3协议payload

test.txt：用于IIOP协议探测

Weblogic_Vuln_Scan：借用https://github.com/FunctFan/Weblogic_Vuln_Scan.git  weblogic-scan升级版

Tips：建议在linux下执行，windows下日志输出会有些乱序问题，后面我会再改的（如果有时间的话*——*

add some files to suppost burpsuite
