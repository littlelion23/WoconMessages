#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask import Flask, request, make_response
import json
import time
import xml.etree.cElementTree as ET
from WXBizJsonMsgCrypt import WXBizJsonMsgCrypt
import sys
import os
import requests

app = Flask(__name__)

# === 配置参数区 ===
# 请将以下参数修改为您在企业微信后台配置的实际参数
TOKEN = "**********************"           # 您在企业微信后台设置的Token
ENCODING_AES_KEY = "**************************"  # 您在企业微信后台设置的EncodingAESKey
CORP_ID = "********************"      # 您的企业ID

# 会话存档配置参数
FINANCE_CORP_ID = "****************"  # 企业ID，用于会话存档
FINANCE_SECRET = "************************"  # 会话存档Secret，需要在企业微信后台获取
RSA_PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
********************
-----END PRIVATE KEY-----"""  # 用于解密encrypt_random_key的RSA私钥

# Linux系统下的路径配置
SDK_LIB_PATH = os.path.join(os.path.dirname(__file__), 'sdk_x86_v3_20250205', 'C_sdk', 'libWeWorkFinanceSdk_C.so')  # 默认使用标准路径，如需指定具体路径，请设置此变量

# 初始化加解密器
wxcpt_json = WXBizJsonMsgCrypt(TOKEN, ENCODING_AES_KEY, CORP_ID)

from callback_python3.WXBizMsgCrypt import WXBizMsgCrypt
wxcpt_xml = WXBizMsgCrypt(TOKEN, ENCODING_AES_KEY, CORP_ID)

# 导入会话存档SDK
from finance_client import WeWorkFinanceSDK, rsa_decrypt_chat_data
finance_sdk = None  # 全局SDK实例

# 日志文件路径
DEBUG_LOG_PATH = os.path.join(os.path.dirname(__file__), 'wechat_debug.log')
LOG_FILE_PATH = os.path.join(os.path.dirname(__file__), 'wechat_messages.log')
DEBUG_TXT_PATH = os.path.join(os.path.dirname(__file__), 'wechat_messages_full.txt')

# 创建日志文件（如果不存在）
if not os.path.exists(LOG_FILE_PATH):
    open(LOG_FILE_PATH, 'w', encoding='utf-8').close()
if not os.path.exists(DEBUG_LOG_PATH):
    open(DEBUG_LOG_PATH, 'w', encoding='utf-8').close()
if not os.path.exists(DEBUG_TXT_PATH):
    open(DEBUG_TXT_PATH, 'w', encoding='utf-8').close()

def log_debug(message):
    """
    通用日志记录函数，将消息同时打印到控制台和保存到日志文件
    """
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    log_message = f"[{timestamp}] {message}"
    print(log_message)
    
    # 写入调试日志文件
    with open(DEBUG_LOG_PATH, 'a', encoding='utf-8') as f:
        f.write(log_message + '\n')

@app.route('/wechat/callback', methods=['GET', 'POST'])
def wechat_callback():
    """
    企业微信回调处理入口
    支持GET（URL验证）和POST（消息接收）两种方法
    """
    # 获取URL参数
    msg_signature = request.args.get('msg_signature')
    timestamp = request.args.get('timestamp')
    nonce = request.args.get('nonce')

    print(f"收到请求 - 方法: {request.method}, 参数: signature={msg_signature}, timestamp={timestamp}, nonce={nonce}")
    log_debug(f"收到请求 - 方法: {request.method}, 参数: signature={msg_signature}, timestamp={timestamp}, nonce={nonce}")

    if request.method == 'GET':
        # URL验证请求处理
        return handle_url_verification(msg_signature, timestamp, nonce)
    elif request.method == 'POST':
        # 消息接收处理
        log_debug(f"消息接收处理开始")
        return handle_message_reception(request, msg_signature, timestamp, nonce)

def handle_url_verification(msg_signature, timestamp, nonce):
    """
    处理URL验证请求
    同时支持JSON和XML格式的验证
    """
    echostr = request.args.get('echostr')
    print(f"开始URL验证，echostr: {echostr}")
    log_debug(f"开始URL验证，echostr: {echostr}")

    # 先尝试使用XML解密器验证
    try:
        ret, sEchoStr = wxcpt_xml.VerifyURL(msg_signature, timestamp, nonce, echostr)
        if ret == 0:
            log_debug("URL验证成功 (XML)")
            # 验证成功，返回解密后的echostr
            save_message_to_log(sEchoStr)
            log_debug(f"解密成功，echostr: {sEchoStr}")
            response = make_response(sEchoStr)
            response.headers['Content-Type'] = 'text/plain'
            return response
    except Exception as e:
        log_debug(f"XML URL验证异常: {str(e)}")
    
    # 如果XML验证失败，尝试使用JSON解密器验证
    try:
        ret, sEchoStr = wxcpt_json.VerifyURL(msg_signature, timestamp, nonce, echostr)
        if ret == 0:
            log_debug("URL验证成功 (JSON)")
            save_message_to_log(sEchoStr)
            log_debug(f"解密成功，echostr: {sEchoStr}")
            response = make_response(sEchoStr)
            response.headers['Content-Type'] = 'text/plain'
            return response
    except Exception as e:
        log_debug(f"JSON URL验证异常: {str(e)}")

def handle_message_reception(request, msg_signature, timestamp, nonce):
    """
    处理消息接收请求
    """
    try:
        # 获取POST数据
        post_data = request.data.decode('utf-8')
        print(f"收到POST数据: {post_data}")
        log_debug(f"收到POST数据: {post_data}")

        # 尝试先用XML解密器解密
        ret, decrypted_msg = wxcpt_xml.DecryptMsg(post_data, msg_signature, timestamp, nonce)
        
        # 如果XML解密失败，尝试用JSON解密器解密
        if ret != 0:
            print(f"XML解密失败，错误码: {ret}，尝试JSON解密")
            log_debug(f"XML解密失败，错误码: {ret}，尝试JSON解密")
            ret, decrypted_msg = wxcpt_json.DecryptMsg(post_data, msg_signature, timestamp, nonce)
        
        if ret != 0:
            print(f"消息解密失败，错误码: {ret}")
            log_debug(f"消息解密失败，错误码: {ret}")
            return f"解密失败，错误码: {ret}", 400

        log_debug(f"消息解密成功: {decrypted_msg}")
        print(f"消息解密成功: {decrypted_msg}")
        
        # 在收到回调消息后，触发主动拉取以确保消息完整性
        log_debug("开始主动拉取消息")
        print("开始主动拉取消息")
        trigger_pull_chat()

        # # 处理解密后的消息
        # response_msg = process_decrypted_message(decrypted_msg)
        # # 加密回复消息
        # ret, encrypted_response = wxcpt.EncryptMsg(response_msg, nonce, timestamp)
        # if ret != 0:
        #     log_debug(f"消息加密失败，错误码: {ret}")
        #     return f"加密失败，错误码: {ret}", 500
        #
        # log_debug(f"回复消息加密成功: {encrypted_response}")
        #
        # # 返回加密后的回复消息
        # response = make_response(encrypted_response)
        # response.headers['Content-Type'] = 'application/json'
        return decrypted_msg

    except Exception as e:
        log_debug(f"消息处理异常: {str(e)}")
        return f"处理异常: {str(e)}", 500

# def process_decrypted_message(decrypted_msg):
#     """
#     处理解密后的消息，构造回复消息
#     根据企业微信回调消息格式处理
#     """
#     try:
#         # 解析解密后的消息
#         msg_dict = json.loads(decrypted_msg)
#         print(f"解析消息: {msg_dict}")
#
#         # 保存消息到日志文件
#         save_message_to_log(msg_dict)
#         # 同时保存完整消息到txt文件
#         save_message_to_txt(msg_dict)
#
#         # 获取消息基本信息，根据企业微信回调消息格式
#         # 首先检查是否为回调消息格式（包含msgid字段）
#         if 'msgid' in msg_dict:
#             # 企业微信回调消息格式
#             from_user = msg_dict.get('from', '')
#             msg_type = msg_dict.get('msgtype', '')
#         else:
#             # 普通消息格式（如用户发送消息）
#             from_user = msg_dict.get('FromUserName', '')
#             msg_type = msg_dict.get('MsgType', '')
#
#         create_time = int(time.time())
#
#         print(f"消息类型: {msg_type}, 发送者: {from_user}")
#
#         # 根据消息类型构造不同的回复
#         # 首先检查是否为回调消息格式（包含msgid字段）
#         if 'msgid' in msg_dict:
#             # 这是企业微信回调消息格式
#             if msg_type == 'text':
#                 # 文本消息处理
#                 text_data = msg_dict.get('text', {})
#                 content = text_data.get('content', '')
#                 print(f"收到文本消息: {content}")
#
#                 # 构造回复消息
#                 reply_content = f"收到了您的消息：{content}\n这是一条自动回复"
#
#             elif msg_type in ['image', 'voice', 'video']:
#                 # 媒体消息处理
#                 print(f"收到{msg_type}类型的消息")
#                 if msg_type == 'image':
#                     reply_content = f"收到了图片消息"
#                 elif msg_type == 'voice':
#                     reply_content = f"收到了语音消息"
#                 elif msg_type == 'video':
#                     reply_content = f"收到了视频消息"
#
#             elif msg_type == 'revoke':
#                 # 撤回消息处理
#                 revoke_data = msg_dict.get('revoke', {})
#                 pre_msgid = revoke_data.get('pre_msgid', '')
#                 print(f"收到撤回消息，原消息ID: {pre_msgid}")
#                 reply_content = f"检测到消息撤回，原消息ID: {pre_msgid}"
#
#             else:
#                 # 其他回调消息类型
#                 reply_content = f"收到了{msg_type}类型的消息，暂时无法处理该类型消息"
#         else:
#             # 这可能是普通的消息格式（如用户发送消息）
#             msg_type = msg_dict.get('MsgType', '')
#             if msg_type == 'text':
#                 # 文本消息处理
#                 content = msg_dict.get('Content', '')
#                 print(f"收到文本消息: {content}")
#
#                 # 构造回复消息
#                 reply_content = f"收到了您的消息：{content}\n这是一条自动回复"
#
#             elif msg_type == 'event':
#                 # 事件消息处理
#                 event = msg_dict.get('Event', '')
#                 print(f"收到事件: {event}")
#
#                 if event == 'subscribe':
#                     reply_content = "欢迎关注！感谢您的关注！"
#                 else:
#                     reply_content = f"收到了事件：{event}"
#
#             else:
#                 # 其他类型消息处理
#                 reply_content = f"收到了{msg_type}类型的消息，暂时无法处理该类型消息"
#
#         # 构造回复消息JSON
#         response_data = {
#             "ToUserName": from_user,
#             "FromUserName": CORP_ID,
#             "CreateTime": int(time.time()),
#             "MsgType": "text",
#             "Content": reply_content,
#             "MsgId": str(int(time.time() * 1000000))  # 生成唯一的MsgId
#         }
#
#         response_json = json.dumps(response_data, ensure_ascii=False)
#         print(f"构造回复消息: {response_json}")
#         return response_json
#
#     except json.JSONDecodeError as e:
#         print(f"JSON解析错误: {str(e)}")
#         # 构造错误回复
#         error_response = {
#             "ToUserName": "",
#             "FromUserName": CORP_ID,
#             "CreateTime": int(time.time()),
#             "MsgType": "text",
#             "Content": "消息处理出现错误",
#             "MsgId": str(int(time.time() * 1000000)),
#             "AgentID": ""
#         }
#         return json.dumps(error_response, ensure_ascii=False)
#     except Exception as e:
#         print(f"消息处理错误: {str(e)}")
#         # 构造错误回复
#         error_response = {
#             "ToUserName": "",
#             "FromUserName": CORP_ID,
#             "CreateTime": int(time.time()),
#             "MsgType": "text",
#             "Content": "消息处理出现未知错误",
#             "MsgId": str(int(time.time() * 1000000)),
#             "AgentID": ""
#         }
#         return json.dumps(error_response, ensure_ascii=False)

def save_message_to_log(msg_dict):
    """
    将消息保存到日志文件
    根据企业微信回调消息格式进行解析和记录
    """
    try:
        # 提取消息字段，按照企业微信回调消息格式
        msgid = msg_dict.get('msgid', '')
        action = msg_dict.get('action', '')
        from_user = msg_dict.get('from', '')
        to_list = msg_dict.get('tolist', [])
        roomid = msg_dict.get('roomid', '')
        msgtime = msg_dict.get('msgtime', '')
        msgtype = msg_dict.get('msgtype', '')
        
        # 根据消息类型提取内容
        content = ''
        if msgtype == 'text':
            text_data = msg_dict.get('text', {})
            content = text_data.get('content', '')
        elif msgtype == 'image':
            image_data = msg_dict.get('image', {})
            content = f"图片消息 - MD5: {image_data.get('md5sum', '')}, 大小: {image_data.get('filesize', 0)} bytes"
        elif msgtype == 'voice':
            voice_data = msg_dict.get('voice', {})
            content = f"语音消息 - 播放时长: {voice_data.get('play_length', 0)}秒, 大小: {voice_data.get('voice_size', 0)} bytes"
        elif msgtype == 'video':
            video_data = msg_dict.get('video', {})
            content = f"视频消息 - 播放时长: {video_data.get('play_length', 0)}秒, 大小: {video_data.get('filesize', 0)} bytes"
        elif msgtype == 'revoke':
            revoke_data = msg_dict.get('revoke', {})
            content = f"撤回消息 - 原消息ID: {revoke_data.get('pre_msgid', '')}"
        else:
            # 对于其他类型消息，尝试直接获取content字段
            content = msg_dict.get('content', str(msg_dict))
        
        # 构造日志条目
        log_entry = {
            "msgid": msgid,
            "action": action,
            "from": from_user,
            "tolist": to_list,
            "roomid": roomid,
            "msgtime": msgtime,
            "msgtype": msgtype,
            "content": content,
            "received_at": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        }
        
        # 写入日志文件
        with open(LOG_FILE_PATH, 'a', encoding='utf-8') as f:
            f.write(json.dumps(log_entry, ensure_ascii=False) + '\n')
            
    except Exception as e:
        print(f"保存消息到日志文件时出错: {str(e)}")

def save_message_to_txt(msg_dict):
    """
    将解密后的完整消息直接保存到txt文件
    """
    try:
        # 直接将解密后的完整消息内容写入txt文件
        with open(DEBUG_TXT_PATH, 'a', encoding='utf-8') as f:
            # 将完整的消息字典以JSON格式写入文件
            f.write(json.dumps(msg_dict, ensure_ascii=False) + '\n')
            
    except Exception as e:
        print(f"保存完整消息到txt文件时出错: {str(e)}")


# === 企业微信会话存档功能 ===

# 用于存储当前拉取的消息序列号
CURRENT_SEQ_FILE = os.path.join(os.path.dirname(__file__), 'current_seq.txt')

def get_current_seq():
    """
    获取当前消息序列号，用于下一次拉取
    """
    try:
        if os.path.exists(CURRENT_SEQ_FILE):
            with open(CURRENT_SEQ_FILE, 'r') as f:
                seq = int(f.read().strip())
                return seq
        else:
            # 如果文件不存在，从0开始
            return 0
    except Exception as e:
        log_debug(f"读取当前序列号失败: {e}")
        return 0

def update_current_seq(seq):
    """
    更新当前消息序列号
    """
    try:
        with open(CURRENT_SEQ_FILE, 'w') as f:
            f.write(str(seq))
    except Exception as e:
        log_debug(f"更新序列号失败: {e}")

def init_finance_sdk():
    """
    初始化会话存档SDK
    """
    global finance_sdk
    if finance_sdk is None:
        try:
            # 使用配置的库路径初始化SDK
            finance_sdk = WeWorkFinanceSDK(sdk_lib_path=SDK_LIB_PATH)
            ret = finance_sdk.init(FINANCE_CORP_ID, FINANCE_SECRET)
            if ret != 0:
                print(f"初始化会话存档SDK失败，错误码: {ret}")
                log_debug(f"初始化会话存档SDK失败，错误码: {ret}")
                return False
            print("会话存档SDK初始化成功")
            log_debug("会话存档SDK初始化成功")
            return True
        except Exception as e:
            print(f"初始化会话存档SDK异常: {e}")
            log_debug(f"初始化会话存档SDK异常: {e}")
            return False
    return True

def trigger_pull_chat():
    """
    触发主动拉取聊天记录
    在收到实时回调后调用，以确保消息的完整性
    """
    try:
        import threading

        # 创建一个后台线程来执行拉取，避免阻塞当前回调处理
        def pull_task():
            try:
                # 初始化SDK
                if not init_finance_sdk():
                    log_debug("初始化会话存档SDK失败")
                    return

                # 获取当前序列号
                seq = get_current_seq()

                # 拉取聊天记录
                ret, chat_data = finance_sdk.get_chat_data(seq=seq, limit=200)

                if ret == 0 and chat_data and 'chatdata' in chat_data:
                    # 遍历聊天记录并解密
                    log_debug("已拉取到最近200条记录开始解密")
                    for chat_record in chat_data['chatdata']:
                        encrypt_random_key = chat_record.get('encrypt_random_key')
                        encrypt_chat_msg = chat_record.get('encrypt_chat_msg')
                        #log_debug(f"已经获取参数encrypt_random_key：{encrypt_random_key}")
                        #log_debug(f"已经获取参数encrypt_chat_msg：{encrypt_chat_msg}")

                        if encrypt_random_key and encrypt_chat_msg:
                            # 解密encrypt_random_key
                            decrypted_key = rsa_decrypt_chat_data(encrypt_random_key, RSA_PRIVATE_KEY)
                            if decrypted_key:
                                # 解密聊天消息
                                ret, decrypted_msg = finance_sdk.decrypt_data(decrypted_key, encrypt_chat_msg)
                                log_debug(f"解密聊天消息成功：{decrypted_msg}")
                                if ret == 0:
                                    # 保存解密后的消息
                                    save_message_to_log(decrypted_msg)
                                # 检查消息是否包含群ID，如果是群聊消息则获取群信息
                                if isinstance(decrypted_msg, dict):
                                    roomid = decrypted_msg.get('roomid', '')
                                    if roomid:  # 如果消息包含群ID
                                        log_debug(f"检测到群聊消息，群ID: {roomid}")
                                        access_token = get_access_token()
                                        if access_token:
                                            group_info = get_group_chat_info(access_token, roomid)
                                            if group_info:
                                                # 将群信息与消息信息一起记录
                                                log_debug(f"群信息查询结果: {group_info}")
                                                # 同时记录消息和群信息的组合
                                                combined_info = {
                                                    "message": decrypted_msg,
                                                    "group_info": group_info
                                                }
                                                log_debug(f"消息与群信息组合: {combined_info}")
                                                # 保存组合信息到txt文件
                                                save_message_to_txt(combined_info)

                    # 更新当前seq值
                    max_seq = max([record['seq'] for record in chat_data['chatdata']] or [0])
                    update_current_seq(max_seq)

                    log_debug(f"主动拉取成功，处理了 {len(chat_data['chatdata'])} 条记录，最大seq: {max_seq}")
                else:
                    log_debug(f"主动拉取无新数据，错误码: {ret}")
            except Exception as e:
                log_debug(f"主动拉取任务异常: {e}")

        # 启动后台线程执行拉取任务
        thread = threading.Thread(target=pull_task)
        thread.daemon = True
        thread.start()

        log_debug("已触发主动拉取任务")
    except Exception as e:
        log_debug(f"触发主动拉取异常: {e}")

# === 企业微信会话存档功能 ===

# === 企业微信获取群信息功能 ===
# 群聊信息查询配置参数
GROUP_CHAT_SECRET = "tgZikbk9cJ4khVVf1dNeDRS2mWmU-QYh8eEKT2TMVio"  # 会话内容存档应用的Secret，用于获取access_token
def get_access_token():
    """
    获取企业微信access_token
    参数说明：
    - corpid: 企业ID (对应代码中的CORP_ID)
    - corpsecret: 应用的凭证密钥 (对应代码中的GROUP_CHAT_SECRET)
    权限说明：每个应用有独立的secret，所以每个应用的access_token应该分开来获取

    返回结果：
    {
      "errcode": 0,        # 错误码，0表示成功
      "errmsg": "",        # 错误信息
      "access_token": "accesstoken000001",  # 获取到的凭证，最长为512字节
      "expires_in": 7200   # 凭证的有效时间（秒）
    }

    出错返回示例：
    {
      "errcode": 40091,
      "errmsg": "secret is invalid"
    }
    """
    url = f"https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid={CORP_ID}&corpsecret={GROUP_CHAT_SECRET}"
    try:
        response = requests.get(url)
        result = response.json()

        if result.get('errcode') == 0:
            log_debug(f"获取access_token成功: {result.get('access_token')}")
            return result.get('access_token')
        else:
            log_debug(f"获取access_token失败: {result}")
            return None
    except Exception as e:
        log_debug(f"获取access_token异常: {str(e)}")
        return None

def get_group_chat_info(access_token, roomid):
    """
    获取群聊信息
    请求方式：POST（HTTPS）
    请求地址：https://qyapi.weixin.qq.com/cgi-bin/msgaudit/groupchat/get?access_token=ACCESS_TOKEN
    请求示例：
    {
      "roomid": "wrNplhCgAAIVZohLe57zKnvIV7xBKrig"
    }

    参数说明：
    - access_token: 调用接口凭证 (通过get_access_token获取)
    - roomid: 待查询的群id (从会话内容存档中获取到的roomid)

    权限说明：企业需要使用会话内容存档应用secret所获取的access_token来调用

    返回结果：
    {
      "roomname": "蓦然回首",  # roomid对应的群名称
      "creator": "ZhangWenChao",  # roomid对应的群创建者，userid
      "room_create_time": 1592361604,  # roomid对应的群创建时间
      "notice": "",  # roomid对应的群公告
      "members": [    # roomid对应的群成员列表
        {
          "memberid": "ZhangWenChao",  # roomid群成员的id，userid
          "jointime": 1592361605       # roomid群成员的入群时间
        },
        {
          "memberid": "xujinsheng",
          "jointime": 1592377076
        }
      ],
      "errcode": 0,
      "errmsg": "ok"
    }

    错误说明：
    返回码 301052 表示会话存档已过期
    """
    url = f"https://qyapi.weixin.qq.com/cgi-bin/msgaudit/groupchat/get?access_token={access_token}"
    data = {
        "roomid": roomid
    }
    try:
        response = requests.post(url, json=data)
        result = response.json()

        if result.get('errcode') == 0:
            log_debug(f"获取群聊信息成功: {result}")
            return result
        else:
            log_debug(f"获取群聊信息失败: {result}")
            return result
    except Exception as e:
        log_debug(f"获取群聊信息异常: {str(e)}")
        return None
# === 企业微信获取群信息功能 ===


if __name__ == '__main__':
    # 开发环境下直接运行
    app.run(host='0.0.0.0', port=9530, debug=True)

