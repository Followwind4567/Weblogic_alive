source: https://github.com/rabbitmask/WeblogicScan

# weblogicScaner

[简体中文](./README.md) | English

As of March 7, 2020, weblogic Vulnerability Scanning Tool. If there is an unrecorded and open POC vulnerability, please submit issue.

Some bug fixes were made, some POC did not take effect, or configuration errors. I checked before and found that some POC could not be used. In this project, some modifications have been made to the script to improve the accuracy.

**Note**：Some vulnerabilities require multiple tests to verify due to stability reasons.

Currently detectable vulnerabilitys are (some non-principles detection, manual verification required):

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

# Quick start

### Required

+ python >= 3.6

In the project directory and use the following command to install the dependent libraries

```
$ pip3 install requests
```

### Usage

```
usage: ws.py [-h] -t TARGETS [TARGETS ...]
             [-v VULNERABILITY [VULNERABILITY ...]] [-o OUTPUT]

optional arguments:
  -h, --help            show this help message and exit
  -t TARGETS [TARGETS ...], --targets TARGETS [TARGETS ...]
                        target, or targets file(default port 7001). eg.
                        127.0.0.1:7001
  -v VULNERABILITY [VULNERABILITY ...], --vulnerability VULNERABILITY [VULNERABILITY ...]
                        vulnerability name. eg. "weblogic administrator
                        console"
  -o OUTPUT, --output OUTPUT
                        Path to json output(default without output).
```

# Example

![image](https://user-images.githubusercontent.com/45038279/112823212-964f5e00-90bb-11eb-92e6-52aaa6b9d784.png)

