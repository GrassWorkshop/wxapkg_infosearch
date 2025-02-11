# -*- coding: utf-8 -*-

import os
import sys
import re
import argparse

def banner():
    info = """
                            _             _        __                              _     
                           | |           (_)      / _|                            | |    
 __      ____  ____ _ _ __ | | ____ _     _ _ __ | |_ ___  ___  ___  __ _ _ __ ___| |__  
 \ \ /\ / /\ \/ / _` | '_ \| |/ / _` |   | | '_ \|  _/ _ \/ __|/ _ \/ _` | '__/ __| '_ \ 
  \ V  V /  >  < (_| | |_) |   < (_| |   | | | | | || (_) \__ \  __/ (_| | | | (__| | | |
   \_/\_/  /_/\_\__,_| .__/|_|\_\__, |   |_|_| |_|_| \___/|___/\___|\__,_|_|  \___|_| |_|
                     | |         __/ |_____                                              
                     |_|        |___/______|                                             
"""
    print(info)


# 定义规则字典
relist = {
    # ======== 自定义 规则 ========
    "httplist": "\"http.://.*?\"", "urllist": "\".*?[^http]/.*?\\?.*?=\"", "apikeylist": "api.*?key.*?=",
    "apikeylist": "api.*?key.*?:",
    "userpwdlist": "user.*?=\".*?\"", "userpwdlist": "passw.*?=\".*?\"",
    "accesskey": "access.*?key.*?=", "accesskey": "access.*?key.*?:",
    "tokenkey": "token.*?key.*?=", "tokenkey": "token.*?key.*?:",
    "apipath": "\"[/|]api.*?/.*?[/|]\"", "secret": "secret[id|key].*?=.*?\".*?\"",
    "secret": "secret[id|key].*?:.*?\".*?\"",
    # ======== findsomething 规则 ========
    "sfz": "['\"]((\d{8}(0\d|10|11|12)([0-2]\d|30|31)\d{3}$)|(\d{6}(18|19|20)\d{2}(0[1-9]|10|11|12)([0-2]\d|30|31)\d{3}(\d|X|x)))['\"]",
    "mobile": "['\"](1(3([0-35-9]\d|4[1-8])|4[14-9]\d|5([\d]\d|7[1-79])|66\d|7[2-35-8]\d|8\d{2}|9[89]\d)\d{7})['\"]",
    "mail": "['\"][a-zA-Z0-9\._\-]*@[a-zA-Z0-9\._\-]{1,63}\.((?!js|css|jpg|jpeg|png|ico)[a-zA-Z]{2,})['\"]",
    "ip_port": "['\"]\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}['\"]",
    "ip_port": "['\"]\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\:\d{1,5}['\"]",
    "domain": "['\"][a-zA-Z0-9\-\.]*?\.(xin|com|cn|net|com.cn|vip|top|cc|shop|club|wang|xyz|luxe|site|news|pub|fun|online|win|red|loan|ren|mom|net.cn|org|link|biz|bid|help|tech|date|mobi|so|me|tv|co|vc|pw|video|party|pics|website|store|ltd|ink|trade|live|wiki|space|gift|lol|work|band|info|click|photo|market|tel|social|press|game|kim|org.cn|games|pro|men|love|studio|rocks|asia|group|science|design|software|engineer|lawyer|fit|beer|我爱你|中国|公司|网络|在线|网址|网店|集团|中文网)['\"]",
    "path": "['\"]\/[^\/\>\< \)\(\{\}\,\'\"\\]([^\>\< \)\(\{\}\,\'\"\\])*?['\"]",
    "url": "['\"](([a-zA-Z0-9]+:)?\/\/)?[a-zA-Z0-9\-\.]*?\.(xin|com|cn|net|com.cn|vip|top|cc|shop|club|wang|xyz|luxe|site|news|pub|fun|online|win|red|loan|ren|mom|net.cn|org|link|biz|bid|help|tech|date|mobi|so|me|tv|co|vc|pw|video|party|pics|website|store|ltd|ink|trade|live|wiki|space|gift|lol|work|band|info|click|photo|market|tel|social|press|game|kim|org.cn|games|pro|men|love|studio|rocks|asia|group|science|design|software|engineer|lawyer|fit|beer|我爱你|中国|公司|网络|在线|网址|网店|集团|中文网)(\/.*?)?['\"]",
    "jwt": "['\"'](ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}|ey[A-Za-z0-9_\/+-]{10,}\.[A-Za-z0-9._\/+-]{10,})['\"']",
    "algorithm": "\W(base64\.encode|base64\.decode|btoa|atob|CryptoJS\.AES|CryptoJS\.DES|JSEncrypt|rsa|KJUR|$\.md5|md5|sha1|sha256|sha512)[\(\.]",
    # ======== HEA 规则 ========
    "Shiro": "(=deleteMe|rememberMe=)",
    "JSON Web Token": "(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}|eyJ[A-Za-z0-9_\/+-]{10,}\.[A-Za-z0-9._\/+-]{10,})",
    "Swagger UI": "((swagger-ui.html)|(\"swagger\":)|(Swagger UI)|(swaggerUi)|(swaggerVersion))",
    "Ueditor": "(ueditor\.(config|all)\.js)",
    "RCE Paramters": "((cmd=)|(exec=)|(command=)|(execute=)|(ping=)|(query=)|(jump=)|(code=)|(reg=)|(do=)|(func=)|(arg=)|(option=)|(load=)|(process=)|(step=)|(read=)|(function=)|(feature=)|(exe=)|(module=)|(payload=)|(run=)|(daemon=)|(upload=)|(dir=)|(download=)|(log=)|(ip=)|(cli=))",
}

# 枚举js文件
def jspath(rootDir):
    jss = []
    for root, dirs, files in os.walk(rootDir):
        for file in files:
            docname = os.path.join(root, file)
            if docname[-4:].find(".js") != -1:
                jss.append(docname)
    return jss

# 匹配关键字符串
def rekeystring(jss=[]):
    search_data = {}
    for key, value in relist.items():
        search_data[key] = []
    for js in jss:
        with open(js, "r", encoding="utf-8") as f:
            txt = f.read()
            for key, value in relist.items():
                search_data[key].append(re.findall(value, txt))
    return search_data

# 信息输出
def outprintf(httplist=[], rule_name=""):
    with open("infolist.txt", "a", encoding="utf-8") as f:
        f.write(f"====={rule_name}=====\n") # 写入规则标题
        for http1 in httplist:
            for http2 in http1:
                if isinstance(http2, tuple):
                    for s1 in http2:
                        f.write(str(s1).strip("\"").rstrip("\"") + "\n") # 输出到控制台
                else:
                    s1 = str(http2).strip("\"").rstrip("\"") + "\n"
                    f.write(s1)
        f.write("\n")  # 每个规则的结束后添加一个空行

    for http1 in httplist: # 输出到控制台
        for http2 in http1:
            if isinstance(http2, tuple):
                for s1 in http2:
                    print(str(s1).strip("\"").rstrip("\"") + "\n")
            else:
                s1 = str(http2).strip("\"").rstrip("\"") + "\n"
                print(s1)

def domain(directory):
    jss = jspath(directory)  # 从命令行传入的目录
    search_data = rekeystring(jss)
    for key, value in relist.items(): # 将匹配的结果写到 infolist.txt 中
        outprintf(search_data[key], key)

def main():
    parser = argparse.ArgumentParser(description="微信小程序源码包 wxapkg 信息收集脚本")
    parser.add_argument("-f", "--folder", required=True, help="指定要扫描的目录路径") # 创建命令行参数解析器
    args = parser.parse_args() # 解析命令行参数
    domain(args.folder) # 运行主逻辑

if __name__ == "__main__":
    banner()
    main()
