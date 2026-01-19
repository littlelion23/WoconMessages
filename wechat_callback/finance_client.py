#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
企业微信会话存档SDK Python封装
用于拉取企业聊天记录和媒体文件
"""
import ctypes
import json
import os
import sys
import base64
from ctypes import c_char_p, c_int, c_ulonglong, c_uint, c_void_p, Structure


class Slice(Structure):
    """对应C SDK中的Slice_t结构体"""
    _fields_ = [
        ("buf", c_char_p),
        ("len", c_int)
    ]


class MediaData(Structure):
    """对应C SDK中的MediaData_t结构体"""
    _fields_ = [
        ("outindexbuf", c_char_p),
        ("out_len", c_int),
        ("data", c_char_p),
        ("data_len", c_int),
        ("is_finish", c_int)
    ]


class WeWorkFinanceSDK:
    """企业微信会话存档SDK封装类"""
    
    def __init__(self, sdk_lib_path=None):
        """
        初始化SDK
        :param sdk_lib_path: SDK动态库路径，默认为当前目录下的libWeWorkFinanceSdk_C.so
        """
        # Linux平台
        if sdk_lib_path is None:
            sdk_lib_path = os.path.join(os.path.dirname(__file__), 'sdk_x86_v3_20250205', 'C_sdk', 'libWeWorkFinanceSdk_C.so')
        if not os.path.exists(sdk_lib_path):
            raise FileNotFoundError(f"未找到Linux版本的企业微信SDK文件: {sdk_lib_path}")
        self._sdk_lib = ctypes.CDLL(sdk_lib_path)
        
        # 定义函数原型
        self._define_function_prototypes()
        
        # SDK实例
        self._sdk_instance = None
    
    def _define_function_prototypes(self):
        """定义C函数原型"""
        
        # NewSdk
        self._sdk_lib.NewSdk.argtypes = []
        self._sdk_lib.NewSdk.restype = c_void_p
        
        # Init
        self._sdk_lib.Init.argtypes = [c_void_p, c_char_p, c_char_p]
        self._sdk_lib.Init.restype = c_int
        
        # GetChatData
        self._sdk_lib.GetChatData.argtypes = [c_void_p, c_ulonglong, c_uint, c_char_p, c_char_p, c_int, c_void_p]
        self._sdk_lib.GetChatData.restype = c_int
        
        # DecryptData
        self._sdk_lib.DecryptData.argtypes = [c_char_p, c_char_p, c_void_p]
        self._sdk_lib.DecryptData.restype = c_int
        
        # GetMediaData
        self._sdk_lib.GetMediaData.argtypes = [c_void_p, c_char_p, c_char_p, c_char_p, c_char_p, c_int, c_void_p]
        self._sdk_lib.GetMediaData.restype = c_int
        
        # DestroySdk
        self._sdk_lib.DestroySdk.argtypes = [c_void_p]
        self._sdk_lib.DestroySdk.restype = None
        
        # NewSlice
        self._sdk_lib.NewSlice.argtypes = []
        self._sdk_lib.NewSlice.restype = c_void_p
        
        # FreeSlice
        self._sdk_lib.FreeSlice.argtypes = [c_void_p]
        self._sdk_lib.FreeSlice.restype = None
        
        # GetContentFromSlice
        self._sdk_lib.GetContentFromSlice.argtypes = [c_void_p]
        self._sdk_lib.GetContentFromSlice.restype = c_char_p
        
        # GetSliceLen
        self._sdk_lib.GetSliceLen.argtypes = [c_void_p]
        self._sdk_lib.GetSliceLen.restype = c_int
        
        # NewMediaData
        self._sdk_lib.NewMediaData.argtypes = []
        self._sdk_lib.NewMediaData.restype = c_void_p
        
        # FreeMediaData
        self._sdk_lib.FreeMediaData.argtypes = [c_void_p]
        self._sdk_lib.FreeMediaData.restype = None
        
        # MediaData相关函数
        self._sdk_lib.GetOutIndexBuf.argtypes = [c_void_p]
        self._sdk_lib.GetOutIndexBuf.restype = c_char_p
        
        self._sdk_lib.GetData.argtypes = [c_void_p]
        self._sdk_lib.GetData.restype = c_char_p
        
        self._sdk_lib.GetDataLen.argtypes = [c_void_p]
        self._sdk_lib.GetDataLen.restype = c_int
        
        self._sdk_lib.IsMediaDataFinish.argtypes = [c_void_p]
        self._sdk_lib.IsMediaDataFinish.restype = c_int
    
    def init(self, corpid, secret):
        """
        初始化SDK
        :param corpid: 企业ID
        :param secret: 会话存档Secret
        :return: 0表示成功，其他值表示失败
        """
        try:
            self._sdk_instance = self._sdk_lib.NewSdk()
            if not self._sdk_instance:
                return -1
            
            ret = self._sdk_lib.Init(self._sdk_instance, corpid.encode('utf-8'), secret.encode('utf-8'))
            return ret
        except Exception as e:
            print(f"初始化SDK异常: {e}")
            return -1
    
    def get_chat_data(self, seq, limit=10, proxy="", passwd="", timeout=10):
        """
        拉取聊天记录
        :param seq: 从指定的seq开始拉取消息，首次使用请使用seq:0
        :param limit: 一次拉取的消息条数，最大值1000条
        :param proxy: 代理链接，如：socks5://10.0.0.1:8081 或 http://10.0.0.1:8081
        :param passwd: 代理账号密码，如 user_name:passwd_123
        :param timeout: 超时时间，单位秒
        :return: (ret_code, chat_data)，ret_code为0表示成功
        """
        if not self._sdk_instance:
            return -1, None
        
        try:
            # 创建Slice对象用于接收数据
            chat_data_slice = self._sdk_lib.NewSlice()
            if not chat_data_slice:
                return -1, None
            
            ret = self._sdk_lib.GetChatData(
                self._sdk_instance,
                seq,
                limit,
                proxy.encode('utf-8') if proxy else b"",
                passwd.encode('utf-8') if passwd else b"",
                timeout,
                chat_data_slice
            )
            
            if ret == 0:
                # 获取内容
                content_ptr = self._sdk_lib.GetContentFromSlice(chat_data_slice)
                content_len = self._sdk_lib.GetSliceLen(chat_data_slice)
                
                if content_ptr and content_len > 0:
                    content = content_ptr[:content_len].decode('utf-8')
                    try:
                        chat_data = json.loads(content)
                    except json.JSONDecodeError:
                        chat_data = content
                else:
                    chat_data = None
            else:
                chat_data = None
            
            # 释放Slice
            self._sdk_lib.FreeSlice(chat_data_slice)
            
            return ret, chat_data
        except Exception as e:
            print(f"拉取聊天记录异常: {e}")
            return -1, None
    
    def decrypt_data(self, encrypt_key, encrypt_msg):
        """
        解密聊天记录
        :param encrypt_key: 使用RSA私钥解密后的encrypt_random_key
        :param encrypt_msg: 加密的聊天消息encrypt_chat_msg
        :return: (ret_code, decrypted_data)，ret_code为0表示成功
        """
        try:
            # 创建Slice对象用于接收解密后的数据
            decrypted_slice = self._sdk_lib.NewSlice()
            if not decrypted_slice:
                return -1, None
            
            ret = self._sdk_lib.DecryptData(
                encrypt_key.encode('utf-8'),
                encrypt_msg.encode('utf-8'),
                decrypted_slice
            )
            
            if ret == 0:
                content_ptr = self._sdk_lib.GetContentFromSlice(decrypted_slice)
                content_len = self._sdk_lib.GetSliceLen(decrypted_slice)
                
                if content_ptr and content_len > 0:
                    decrypted_data = content_ptr[:content_len].decode('utf-8')
                    try:
                        decrypted_data = json.loads(decrypted_data)
                    except json.JSONDecodeError:
                        pass  # 如果不是JSON格式，保持字符串格式
                else:
                    decrypted_data = None
            else:
                decrypted_data = None
            
            # 释放Slice
            self._sdk_lib.FreeSlice(decrypted_slice)
            
            return ret, decrypted_data
        except Exception as e:
            print(f"解密聊天记录异常: {e}")
            return -1, None
    
    def get_media_data(self, sdk_file_id, save_path, proxy="", passwd="", timeout=5):
        """
        拉取媒体文件
        :param sdk_file_id: 从聊天记录中获取的sdkfileid
        :param save_path: 媒体文件保存路径
        :param proxy: 代理链接
        :param passwd: 代理账号密码
        :param timeout: 超时时间，单位秒
        :return: 0表示成功，其他值表示失败
        """
        if not self._sdk_instance:
            return -1
        
        try:
            index = ""
            is_finish = 0
            
            while is_finish == 0:
                # 创建MediaData对象
                media_data = self._sdk_lib.NewMediaData()
                if not media_data:
                    return -1
                
                ret = self._sdk_lib.GetMediaData(
                    self._sdk_instance,
                    index.encode('utf-8') if index else b"",
                    sdk_file_id.encode('utf-8'),
                    proxy.encode('utf-8') if proxy else b"",
                    passwd.encode('utf-8') if passwd else b"",
                    timeout,
                    media_data
                )
                
                if ret != 0:
                    self._sdk_lib.FreeMediaData(media_data)
                    return ret
                
                # 获取数据
                data_ptr = self._sdk_lib.GetData(media_data)
                data_len = self._sdk_lib.GetDataLen(media_data)
                is_finish = self._sdk_lib.IsMediaDataFinish(media_data)
                
                # 获取下次拉取需要的索引
                outindex_ptr = self._sdk_lib.GetOutIndexBuf(media_data)
                if outindex_ptr:
                    index = outindex_ptr.decode('utf-8')
                else:
                    index = ""
                
                # 写入文件
                if data_ptr and data_len > 0:
                    with open(save_path, 'ab') as f:
                        f.write(data_ptr[:data_len])
                
                # 释放MediaData
                self._sdk_lib.FreeMediaData(media_data)
            
            return 0
        except Exception as e:
            print(f"拉取媒体文件异常: {e}")
            return -1
    
    def destroy(self):
        """销毁SDK实例"""
        if self._sdk_instance:
            self._sdk_lib.DestroySdk(self._sdk_instance)
            self._sdk_instance = None


def rsa_decrypt_chat_data(encrypt_key, private_key_pem):
    """
    使用RSA私钥解密encrypt_key
    这是一个示例函数，实际使用时需要根据你的私钥格式进行调整
    """
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import serialization
        import base64
        
        # 如果encrypt_key是base64编码的，需要先解码
        if isinstance(encrypt_key, str) and len(encrypt_key) > 256:  # 假设是base64编码
            encrypted_bytes = base64.b64decode(encrypt_key)
        else:
            encrypted_bytes = encrypt_key.encode('utf-8') if isinstance(encrypt_key, str) else encrypt_key
        
        # 加载私钥
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8') if isinstance(private_key_pem, str) else private_key_pem,
            password=None
        )
        
        # 解密
        decrypted_bytes = private_key.decrypt(
            encrypted_bytes,
            padding=padding.PKCS1v15()
        )
        
        # 返回解密后的字符串
        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        print(f"RSA解密失败: {e}")
        return None


def main():
    """示例用法"""
    # 初始化SDK
    sdk = WeWorkFinanceSDK()
    
    # 请替换为你的企业ID和会话存档Secret
    corpid = "your_corpid"
    secret = "your_secret"
    
    ret = sdk.init(corpid, secret)
    if ret != 0:
        print(f"初始化失败，错误码: {ret}")
        return
    
    # 拉取聊天记录 (从seq=0开始，拉取100条)
    ret, chat_data = sdk.get_chat_data(seq=0, limit=100)
    if ret == 0:
        print("聊天记录拉取成功:")
        print(json.dumps(chat_data, ensure_ascii=False, indent=2))
        
        # 如果有聊天记录，尝试解密第一条
        if chat_data and 'chatdata' in chat_data and len(chat_data['chatdata']) > 0:
            first_chat = chat_data['chatdata'][0]
            encrypt_random_key = first_chat.get('encrypt_random_key')
            encrypt_chat_msg = first_chat.get('encrypt_chat_msg')
            
            if encrypt_random_key and encrypt_chat_msg:
                # 这里需要你提供RSA私钥来解密encrypt_random_key
                private_key_pem = "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
                decrypted_key = rsa_decrypt_chat_data(encrypt_random_key, private_key_pem)
                if decrypted_key:
                    ret, decrypted_msg = sdk.decrypt_data(decrypted_key, encrypt_chat_msg)
                    if ret == 0:
                        print("解密成功:")
                        print(json.dumps(decrypted_msg, ensure_ascii=False, indent=2))
    else:
        print(f"拉取聊天记录失败，错误码: {ret}")
    
    # 销毁SDK
    sdk.destroy()


if __name__ == "__main__":
    main()