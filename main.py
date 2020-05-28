#  Copyright (c) 2020. Zhangzhe
#  https://home.asec01.net/

import os
import sys
import base64
from Crypto.PublicKey import RSA
import Crypto.Signature.PKCS1_v1_5 as sign_PKCS1_v1_5
from Crypto import Hash
import pyperclip

# 配置信息
# 程序运行目录
SYSPATH = os.path.dirname(sys.argv[0])
# 私钥文件
PRIVATEKEYPATH = SYSPATH + "\\private.pem"
# 公钥文件
PUBLICKEYPATH = SYSPATH + "\\public.pem"
# 临时文件
TEMPFILEPATH = SYSPATH + "\\temp.txt"
# 消息头
MSGHEAD = "-----BEGIN ZZ RSA SIGNED MESSAGE-----\n"
# 消息签名头
SIGNHEAD = "\n-----BEGIN ZZ RSA SIGNATURE-----\n"
# 消息签名尾
SIGNFOOT = "\n-----END ZZ RSA SIGNATURE-----"
# 文件签名后缀
SIGNFILETYPE = "sig"


# 自定义异常
class KeyException(Exception):
    def __init__(self):
        pass

    def __str__(self):
        return "密钥异常"


# 向用户提问
def yn(txt, default=True):
    if default:
        a = "Y/n"
    else:
        a = "y/N"
    x = input("{} ({}): ".format(txt, a))
    # 转为小写，好判断
    x = x.lower()
    if x == "y":
        return True
    elif x == "n":
        return False
    elif x == "":
        return default
    else:
        return yn(txt, default)


# 生成密钥对
def genRSAKey():
    # 生成密钥对
    x = RSA.generate(2048)
    private_key = x.exportKey()
    public_key = x.publickey().exportKey()
    # 询问用户
    if os.path.exists(PRIVATEKEYPATH):
        if yn("私钥文件已存在，是否覆盖？", False):
            with open(PRIVATEKEYPATH, "wb") as x:
                x.write(private_key)
        else:
            print("不保存私钥文件")
    else:
        with open(PRIVATEKEYPATH, "wb") as x:
            x.write(private_key)
    if os.path.exists(PUBLICKEYPATH):
        if yn("公钥文件已存在，是否覆盖？", False):
            with open(PUBLICKEYPATH, "wb") as x:
                x.write(public_key)
        else:
            print("不保存公钥文件")
    else:
        with open(PUBLICKEYPATH, "wb") as x:
            x.write(public_key)
    if yn("查看私钥？", False):
        print(private_key.decode("utf-8"))
    if yn("查看公钥？", False):
        print(public_key.decode("utf-8"))


# 获得私钥
def getPrivateKey():
    if os.path.exists(PRIVATEKEYPATH):
        # 当私钥文件存在时
        with open(PRIVATEKEYPATH, 'rb')as x:
            private_key = RSA.importKey(x.read())
            return private_key
    else:
        # 当私钥文件不存在时
        if yn("私钥文件不存在，是否生成新的密钥对？", False):
            genRSAKey()
            return getPrivateKey()
        raise KeyException


# 获得公钥
def getPublicKey():
    # 询问是否使用其他私钥
    if yn("是否使用其它公钥进行验证？", False):
        # 输入临时公钥并返回
        return RSA.importKey(notepadOfUserInput("使用公钥覆盖这个文件").encode())
    # 公钥文件存在
    if os.path.exists(PUBLICKEYPATH):
        with open(PUBLICKEYPATH, 'rb')as x:
            public_key = RSA.importKey(x.read())
            return public_key
    # 公钥文件不存在，但私钥文件存在
    elif os.path.exists(PRIVATEKEYPATH):
        print("公钥不存在，使用私钥导出公钥")
        with open(PRIVATEKEYPATH, 'rb')as x:
            private_key = RSA.importKey(x.read())
            new_public_key = private_key.publickey()
            return new_public_key
        pass
    # 密钥文件均不存在
    else:
        if yn("密钥文件不存在，是否生成新的密钥对？", False):
            genRSAKey()
            return getPublicKey()
        raise KeyException


# Base64编码封装
def b64en(s):
    return base64.b64encode(s).decode("utf-8")


# Base64解码封装
def b64de(s):
    return base64.b64decode(s)


# 签名二进制数据
def getSign(data):
    # 取得私钥
    private_key = getPrivateKey()
    # 初始化签名工具
    signer = sign_PKCS1_v1_5.new(private_key)
    # 生成哈希
    rand_hash = Hash.SHA256.new()
    rand_hash.update(data)
    # 签名
    signature = signer.sign(rand_hash)
    # 返回经BASE64编码的签名
    return b64en(signature)


# 签名消息并生成正常人可阅读的格式
def signMessage(plain_text):
    signedMsg = MSGHEAD
    signedMsg += plain_text
    signedMsg += SIGNHEAD
    signedMsg += getSign(plain_text.encode())
    signedMsg += SIGNFOOT
    return signedMsg


# 确认签名是否正确
def checkSign(signature, data):
    # 取得公钥
    public_key = getPublicKey()
    # 初始化签名工具
    verifier = sign_PKCS1_v1_5.new(public_key)
    # 生成哈希
    _rand_hash = Hash.SHA256.new()
    _rand_hash.update(data)
    # 验证
    verify = verifier.verify(_rand_hash, b64de(signature))
    # 返回 True/Fasle
    return verify


# 将签名的消息分割并确认签名是否正确
def checkMessage(msg):
    plain_text = msg.split(MSGHEAD)[1]
    t = plain_text.split(SIGNHEAD)
    plain_text = t[len(t) - 2]
    sign = t[len(t) - 1].split(SIGNFOOT)[0]
    return checkSign(sign, plain_text.encode())


# 调用记事本输入文本
def notepadOfUserInput(temptxt=""):
    # 以写入模式打开临时文件
    file = open(TEMPFILEPATH, 'w')
    # 将临时文本写入
    file.write(temptxt)
    # 关闭文件
    file.close()
    # 调用 Windows 记事本 打开临时文件
    p = os.popen("notepad.exe {}".format(TEMPFILEPATH))
    # 等待进程退出
    p.read()
    # 以只读模式打开临时文件
    file = open(TEMPFILEPATH, 'r')
    # 读取文件
    text = file.read()
    # 关闭文件
    file.close()
    # 将读取结果返回
    return text


# 生成文件的签名文件
def genFileSig(xx):
    # 判断文件路径是否正确
    if not os.path.exists(xx):
        print("文件 {} 不存在！".format(xx))
    else:
        f = None
        # 以二进制只读方式打开文件
        with open(xx, 'rb')as x:
            f = x.read()
        # 签名文件
        sig = getSign(f)
        # 写入签名文件
        with open(xx + "." + SIGNFILETYPE, 'w')as x:
            x.write(sig)
        print("签名完成")


# 确认文件签名是否正确
def checkFileSig(xx):
    # 判断输入的路径是文件路径还是签名文件路径
    t = xx.split(".")
    t = t[len(t) - 1]
    filePath = ""
    signPath = ""
    if t == SIGNFILETYPE:
        signPath = xx
        filePath = xx.split("." + SIGNFILETYPE)[0]
    else:
        filePath = xx
        signPath = xx + "." + SIGNFILETYPE
    print("#" * 30)
    print("文件路径: " + filePath)
    print("签名路径: " + signPath)
    # 判断两种文件是否都存在
    if not os.path.exists(signPath):
        print("签名文件 {} 不存在！".format(signPath))
        return None
    if not os.path.exists(filePath):
        print("文件 {} 不存在！".format(filePath))
        return None
    else:
        f = None
        # 以二进制只读方式打开文件
        with open(filePath, 'rb')as x:
            f = x.read()
        sig = ''
        # 以只读方式打开签名文件
        with open(signPath, 'r')as x:
            sig = x.read()
        # 验证文件
        if checkSign(sig, f):
            print("验证通过！")
        else:
            print("验证失败！")


# 无启动参数时的程序入口
def main():
    print("功能菜单")
    print("0.生成密钥对")
    print("1.签名消息")
    print("2.验证消息签名")
    print("3.签名文件")
    print("4.验证文件签名")
    x = input("请输入序号: ")
    if x == "0":
        genRSAKey()
    elif x == "1":
        # 取得签名结果
        signResult = signMessage(notepadOfUserInput("在这个文档中输入要加密的消息，然后保存并退出"))
        print("签名结果:")
        print(signResult)
        if yn("是否将签名结果放入剪贴板？", False):
            pyperclip.copy(signResult)
            print("已将签名结果放入剪贴板")
    elif x == "2":
        # 验证签名结果
        if checkMessage(notepadOfUserInput("在这个文档中输入要验证的消息与签名，然后保存并退出")):
            print("验证通过！")
        else:
            print("验证失败！")
    elif x == "3":
        xx = input("请输入文件路径:\n")
        xx.replace("\"", "")
        genFileSig(xx)
    elif x == "4":
        xx = input("请输入文件或签名文件路径:\n")
        xx.replace("\"", "")
        checkFileSig(xx)
    else:
        print("输入有误，请重新输入")


# 文件名作为启动参数时的程序入口
def askFileSign(xx):
    print("功能菜单")
    print("0.生成密钥对")
    print("1.签名文件")
    print("2.验证文件签名")
    x = input("请输入序号: ")
    if x == "0":
        # 调用生成密钥对方法
        genRSAKey()
        # 重新进入菜单
        askFileSign(xx)
    elif x == "1":
        # 判断私钥文件是否存在
        if os.path.exists(PRIVATEKEYPATH):
            genFileSig(xx)
        else:
            print("私钥文件 {} 不存在！".format(PRIVATEKEYPATH))
            # 调用生成密钥对方法
            genRSAKey()
            # 重新进入菜单
            askFileSign(xx)
    elif x == "2":
        # 验证文件签名
        checkFileSig(xx)
    else:
        print("输入有误，请重新输入")
        askFileSign(xx)


# 程序入口
if __name__ == '__main__':
    # 当参数为两个的时候
    if len(sys.argv) == 2:
        try:
            # 取第二个参数作为文件路径
            print("目标文件: " + sys.argv[1])
            askFileSign(sys.argv[1])
        # 异常处理
        except Exception as e:
            print("抛出异常: " + str(e))
        input("运行结束，按回车退出")
        sys.exit(0)
    else:
        while True:
            try:
                main()
            except Exception as e:
                print("抛出异常: " + str(e))
            print("\n")
