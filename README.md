# wxapkg_infosearch
一款微信小程序源码包信息收集工具，根据已有项目改编

本项目是由 https://github.com/moyuwa/wechat_appinfo_wxapkg 项目中的信息收集脚本改编而成

感谢这位大佬，侵删

主要区别：
跟原项目脚本相比，本项目将输出的两个文件(一个输出规则名，一个输出结果)合并，每条结果写入对应规则下面，并且添加了换行，使结果看起来更美观一点

添加了参数，-h查看帮助，-f指定目录

用法：
python3 wxapkg_infosearch.py -f 源码包位置

最终输出infolist.txt

![image](https://github.com/user-attachments/assets/233254d9-c447-4ffc-a7af-ec91245bfda0)
