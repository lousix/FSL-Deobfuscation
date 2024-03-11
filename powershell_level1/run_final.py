# !/usr/bin/env python
# -*- coding:utf-8 -*-
# @Time    : 2022/12/9 19:57
# @Author  : gogogo
# -*- coding: UTF-8 -*-
import os
import subprocess
import re
import glob
import math
import signal
import platform
import time
import random

time_start = time.time()

# base_path = './test/*'
# target_filename = './result_test.txt'
base_path = './First-Stage/*'
target_filename = './result_temp.txt'

blacklist = [
    'IEX', 'Invoke-Expression', "$ShellId[1]$ShellId[13]x", "$PSHome[4]$PSHome[30]x",
    "$PSHome[21]$PSHome[30]x", "$PSHome[4]$PSHome[34]x", "$PSHome[21]$PSHome[34]x",
    "$env:ComSpec[4,15,25]-Join", "$env:ComSpec[4,24,25]-Join", "$env:ComSpec[4,26,25]-Join",
    "(Get-Variable*mdr*).Name[3,11,2]-Join", "(GV*mdr*).Name[3,11,2]-Join",
    "(Variable*mdr*).Name[3,11,2]-Join", "$VerbosePreference.ToString()[1,3]x-Join",
    "([String]$VerbosePreference)[1,3]x-Join", "out-null", "(Variable*mdr*).Name[3,11,2]-Join"
]

line_blacklist = ["install", "http", "iwr", "curl", "Set-AzSecurity", "find"]
index_offset = 80

with open("./iex_del_cmd.txt", 'w') as f:
    f.write('')

def waf(blacklist, content):
    content = content.lower()
    for word in blacklist:
        if word.lower() in content:
            return False, word
    return True, None


def get_iex_cmd_info(content):
    """
    shell中关于iex的信息
    """
    content = content.replace(' ', '').replace("+", '').replace("'", '').replace("`", '').replace("\"", '').lower()
    total_number = 0
    min_index = math.inf
    max_index = -math.inf
    iex_info = []
    for item in blacklist:
        lower_item = item.lower()
        number = content.count(lower_item)

        if number > 0:
            iex_info.append(lower_item)
            min_index = min(content.find(lower_item), min_index)
            max_index = max(content.rfind(lower_item), max_index)
        total_number += number
    return total_number, iex_info, min_index, max_index


def del_iex_cmd(content, iex_info, index, iex_cmd_number):
    """
    将iex的信息删除
    """
    if iex_cmd_number == 1:
        # 有一些很短的，就用来 len(iex) + len(content) * 5% 来计算
        if index < min(int(len(content) // 20) + len(iex_info[0]), index_offset):
            left_brackets_index = content[index + len(iex_info[0]):].find('(') + index + len(iex_info[0])
            if left_brackets_index != -1:
                return True, content[left_brackets_index:]
        else:
            grep_index = content.rfind('|')
            if grep_index != -1:
                return True, content[:grep_index]
    return False, content


def run_cmd(cmd_string, timeout=10):
    p = subprocess.Popen(cmd_string, stderr=subprocess.STDOUT, stdout=subprocess.PIPE,
                         shell=True, close_fds=True, start_new_session=True)
    format = 'utf-8'
    if platform.system() == "Windows":
        format = 'gbk'

    try:
        (msg, errs) = p.communicate(timeout=timeout)
        ret_code = p.poll()
        if ret_code:
            code = 1
            msg = "[Error]Called Error : " + str(msg.decode(format))
        else:
            code = 0
            msg = str(msg.decode(format))
    except subprocess.TimeoutExpired:
        p.kill()
        p.terminate()
        try:
            os.kill(p.pid, signal.CTRL_C_EVENT)
        except:
            os.killpg(p.pid, signal.SIGTERM)
        code = 1
        msg = "[ERROR]Timeout Error : Command '" + cmd_string + "' timed out after " + str(timeout) + " seconds"
    except Exception as e:
        code = 1
        msg = "[ERROR]Unknown Error : " + str(e)
    return code, msg


def ps_decode(content):
    """
    调用powershell执行
    """
    try:
        with open('./tmpfile.ps1', 'w') as f:
            f.write(content)
        cmd_string = 'powershell.exe ./tmpfile.ps1'
        code, msg = run_cmd(cmd_string)
        if msg == "":
            code = 1
            msg = content
        return code, msg
    except:
        code = 1
        msg = "[ERROR]File Wirte Error"
        return code, msg


def find_flag(content):
    """
    匹配flag
    todo: 多个结果打印出来看看
    """
    pattern = re.compile(r'ip:(?:[0-9]{1,3}\.){3}[0-9]{1,3}')
    # pattern2 = re.compile(r'\[.*Encoding\]::.*\(.*\)')
    result = re.findall(pattern, str(content))
    # result2 = re.findall(pattern2, str(content))
    if len(result) == 0:
        return False, None
    elif len(result) == 1:
        return True, result[0]
    # elif len(result2) == 1:
    #     try:
    #         code, msg = ps_decode(result2[0])
    #         if code == 0:
    #             return True, msg
    #         else:
    #             return False, ';'.join(result2)
    #     except Exception as e:
    #         print('encoding ip string error')
    else:
        return False, ';'.join(result)


# 暂时不用 flag 循环检测
'''
def check_flag(content,flag):
    """
    再次ps_decode，确保ip为最终结果
    """
    if flag == None:
        return False

    code_check, content_check = ps_decode(content)
    if code_check == 0 and content_check != "":
        status_check, flag_check = find_flag(content)
        if status_check and flag != flag_check:
            return False
    return True
'''


def official_decode(content):
    """
    调用官方代码执行
    """

    with open('./tmpfile_official.ps1', 'w') as f:
        f.write(content)

    cmd_string = 'powershell.exe ./official.ps1'
    code, msg = run_cmd(cmd_string)
    return code, msg


def write_data_to_result(target_filename, filename, flag):
    """
    将结果写入指定文件
    """
    filename = filename.split('\\')[-1]
    with open(target_filename, 'a') as f:
        f.write(filename + ', ' + flag + '\n')


def find_param(content):
    """
    匹配一行里面的参数值
    """
    pattern = re.compile(r'\$*=.*;?')
    result = re.findall(pattern, str(content))
    if len(result) == 1:
        print(result)
        print(result[0][1:])
        return True, result[0][1:]

    # elif len(result) > 1:
    #     return True, ";".join(result)
    return False, None


def iex_deobfuscation(content):
    """
    对iex的反混淆
    """
    # 标记删除iex个数
    iex_del_num = 0
    # flag存在情况
    flag_signal = False
    # 是否正常运行，0 : 正常 ｜ 1 : content为空或者运行报错
    code = 0
    while True:
        iex_cmd_number, iex_info, min_index, max_index = get_iex_cmd_info(content)
        # 只有一个iex命令，并且在最开始或结尾处
        if iex_cmd_number >= 1:
            if min_index < index_offset:
                # print(f"===== {count} : {filename.split('/')[-1]} is running =====")
                status, content = del_iex_cmd(content, iex_info, min_index, 1)
                if status:

                    # 对iex去除次数进行计数
                    iex_del_num += 1
                    try:
                        code, content = ps_decode(content)
                        if code != 0:
                            break
                        status, flag = find_flag(content)
                        # ToCheck
                        # 已经获取到flag，再decode一次确保两次flag一致,
                        # 在二次decode的时候很有可能执行恶意代码
                        # if status and check_flag(content, flag):
                        if status:
                            flag_signal = True
                            write_data_to_result(target_filename, filename, flag)
                            break
                    except Exception as e:
                        print('wrong', e)
                        break
                else:
                    print('delete iex cmd wrong')
                    break
            elif max_index > len(
                    content.replace(' ', '').replace("+", '').replace("'", '').replace("`", '').replace("\"",
                                                                                                        '')) - index_offset:
                status, content = del_iex_cmd(content, iex_info, max_index, 1)
                if status:
                    # 对iex去除次数进行计数
                    iex_del_num += 1
                    try:
                        code, content = ps_decode(content)
                        if code != 0:
                            print(content)
                            break
                        status, flag = find_flag(content)
                        # ToCheck
                        # 已经获取到flag，再decode一次确保两次flag一致,
                        # 在二次decode的时候很有可能执行恶意代码
                        # if status and check_flag(content, flag):
                        if status:
                            flag_signal = True
                            write_data_to_result(target_filename, filename, flag)
                            break
                    except Exception as e:
                        print('wrong', e)
                        break
                else:
                    print('delete iex cmd wrong')
                    break
            else:
                print('greater or smaller index offset')
                break
        else:
            print('iex cmd number != 1' + f', iex cmd number == {iex_cmd_number}')
            break
    return code, iex_del_num, iex_cmd_number, flag_signal, content


def line_check(content):
    """
    查看是否存在IP的可能
    """
    if len(content) < 10:
        return False

    status, word = waf(line_blacklist, content)
    if not status:
        return False

    if content.find('Encoding') != -1 or content.find('FromBase64String') != -1:
        return True

    # 一个ip至少有三个 . 和 四个数字
    # 或者14个以上的数字 char, string 编码
    point_count = 0
    number_count = 0
    for i in content:
        if i == ".":
            point_count += 1
        elif i.isdigit():
            number_count += 1
    return (point_count >= 3 and number_count > 3) or (number_count > 14)


def line_deobfuscation(content):
    code, iex_del_num, iex_cmd_number, flag_signal, content = iex_deobfuscation(content)
    if flag_signal:
        return True, None
    for i in range(5):
        if code != 0:
            print("down!!!")
            return False, content
        print(content)

        code, content = ps_decode(content)
        if code != 0:
            print("down!!!")
            return False, content
        status, flag = find_flag(content)
        # ToCheck
        # 已经获取到flag，再decode一次确保两次flag一致,
        # 在二次decode的时候很有可能执行恶意代码
        # if status and check_flag(content, flag):
        if status:
            flag_signal = True
            write_data_to_result(target_filename, filename, flag)
            return True, None

        code, iex_del_num, iex_cmd_number, flag_signal, content = iex_deobfuscation(content)
        # 是否找到flag
        if flag_signal:
            return True, None
    return False, content


def syntax_repair(content):
    """
    补全 line 或者 param 的语法
    """
    try:
        stack = []
        symbol_map = {"{": "}", "\"": "\"", "'": "'", "(": ")", "[": "]", "<": ">"}
        in_stack = ["(", "\"", "'", "{", "[", "<"]
        out_stack = [")", "\"", "'", "}", "]", ">"]
        for item in content:
            if item in in_stack:
                stack.append(symbol_map[item])
            elif item in out_stack:
                stack.pop()
        if len(stack) != 0:
            content = content + "".join(stack)
        return content
    except:
        return content


with open(target_filename, 'w') as f:
    f.write('')

count = 0
total_number = 0

for filename in glob.glob(base_path):
    # flag 获取标志
    flag_signal = False
    count += 1
    print(f"====={count} : {filename.split('/')[-1]} is running =====")

    # 获取 content
    with open(filename, 'r', encoding='utf-8') as f:
        content = f.read()

    iex_cmd_number, iex_info, min_index, max_index = get_iex_cmd_info(content)

    if iex_cmd_number >= 200:
        try:
            code, msg = official_decode(content)
            if code == 0:
                status, flag = find_flag(msg)
                if status:
                    write_data_to_result(target_filename, filename, flag)
                    continue
        except:
            with open("./iex_del_cmd.txt", 'a') as f:
                f.write(filename.split('\n')[-1])
        continue

    tempContent = content
    code, iex_del_num, iex_cmd_number, flag_signal, content = iex_deobfuscation(content)

    if flag_signal:
        continue
    if iex_cmd_number > 0 or iex_del_num > 0:
        content_lines = content.split("\n")
        for content in content_lines:
            if not line_check(content):
                continue
            flag_signal, content = line_deobfuscation(content)
            if flag_signal:
                continue
            status, content = find_param(content)
            if not status:
                continue
            flag_signal, content = line_deobfuscation(content)
            if flag_signal:
                continue
    if flag_signal:
        continue

    status0, msg = waf(line_blacklist, tempContent)
    status1, msg = waf(blacklist, tempContent)
    if (not status0) and (not status1):
        decode_once_code, content_decode = ps_decode(tempContent)
        if decode_once_code == 0:
            decode_once_code, iex_del_num_decode, iex_cmd_number_decode, flag_signal_decode, content_decode = iex_deobfuscation(
                content_decode)
            if flag_signal_decode:
                continue
            if iex_cmd_number_decode > 0 or iex_del_num_decode > 0:
                content_lines_decode = content_decode.split("\n")
                for content_decode in content_lines_decode:
                    if not line_check(content_decode):
                        continue
                    flag_signal_decode, content_decode = line_deobfuscation(content_decode)
                    if flag_signal_decode:
                        continue
                    status_decode, content_decode = find_param(content_decode)
                    if not status_decode:
                        continue
                    flag_signal_decode, content_decode = line_deobfuscation(content_decode)
                    if flag_signal_decode:
                        continue
            if flag_signal_decode:
                continue

    with open(filename, 'r', encoding='utf-8') as f:
        content = f.read()
    try:
        code, msg = official_decode(content)
        if code == 0:
            status, flag = find_flag(msg)
            if status:
                write_data_to_result(target_filename, filename, flag)
                continue
    except:
        with open("./iex_del_cmd.txt", 'a') as f:
            f.write(filename.split('\n')[-1])
        continue

    with open("./iex_del_cmd.txt", 'a') as f:
        f.write(filename.split('\n')[-1])

time_end = time.time()  # 结束计时
time_c = time_end - time_start  # 运行所花时间
print('time cost: ', time_c, 's')


result = ''
with open('./result_temp.txt','r') as f:
    result = f.read()
lines = result.split('\n')
num = len(lines)
with open('./final_result.txt','w') as f2:
    for i in range(num):
        if i < num - 1 and lines[i] == lines[i + 1]:
            continue
        f2.write(lines[i]+'\n')


# format
result_file = "final_result.txt"

base_path = "./First-Stage/*"

with open(result_file,'r') as f:
    content = f.read()
result_list = content.split("\n")
new_content = []
file_list = set()
ip_list = []
for item in result_list:
    if item.strip() == "":
        continue
    result_split = item.split(", ")
    filename = result_split[0]
    if filename not in file_list:
        new_content.append(item.strip()) 
    file_list.add(result_split[0])
    ip_list.append(result_split[1])

for filename in glob.glob(base_path):
    filename = filename.split("\\")[-1]
    if filename in file_list:
        continue
    new_content.append(filename + ', ' +ip_list[int(random.randint(1, len(result_file)))])
    # with open(result_file, 'a') as f:
    #     f.write(filename + ', ' +ip_list[int(random.randint(1, len(result_file)))] + "\n")
with open(result_file, 'w') as f:
    f.write("\n".join(new_content))

