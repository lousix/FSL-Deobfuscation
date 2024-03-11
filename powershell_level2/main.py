#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : matrix-wd
import glob
import os
import re
import subprocess
import platform
import base64
import math
import zlib


target_filename = './result.txt'
index_offset = 60
blacklist = [
    'IEX', 'Invoke-Expression', "$ShellId[1]$ShellId[13]x", "$PSHome[4]$PSHome[30]x",
    "$PSHome[21]$PSHome[30]x", "$PSHome[4]$PSHome[34]x", "$PSHome[21]$PSHome[34]x",
    "$env:ComSpec[4,15,25]-Join", "$env:ComSpec[4,24,25]-Join", "$env:ComSpec[4,26,25]-Join",
    "(Get-Variable*mdr*).Name[3,11,2]-Join", "(GV*mdr*).Name[3,11,2]-Join",
    "(Variable*mdr*).Name[3,11,2]-Join", "$VerbosePreference.ToString()[1,3]x-Join",
    "([String]$VerbosePreference)[1,3]x-Join", "(Variable*mdr*).Name[3,11,2]-Join", ".${}"
]


def del_iex_cmd(content, iex_info, index, iex_cmd_number):
    """
    将iex的信息删除
    """
    if iex_cmd_number >= 1:
        # 有一些很短的，就用来 len(iex) + len(content) * 5% 来计算
        if index < min(int(len(content)//20) + len(iex_info[0]),index_offset):
            # &((VaRiaBlE '*mDr*').naME[3,11,2]-JoIn'')( (("{42}{7, 后续的payload是以(开始
            left_brackets_index = content[index + len(iex_info[0]):].find('(') + index + len(iex_info[0])
            if left_brackets_index != -1:
                return True, content[left_brackets_index:]
        else:
            grep_index = content.rfind('|')
            if grep_index != -1:
                return True, content[:grep_index]
    return False, content


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


def write_data_to_result(filename, flag):
    """
    将结果写入指定文件
    """
    filename = filename.split('\\')[-1]
    with open(target_filename, 'a') as f:
        f.write(filename + ', ' + flag + '\n')


def find_flag_by_filename(last_files, filename):
    """
    从文件名中找flag
    """
    cur_files = set(glob.glob('./*'))
    diff_files = cur_files - last_files
    # print('diff_files')
    for _file in diff_files:
        with open(_file, 'r') as f:
            content = f.read()
        os.remove(_file)
        # print('content', content)
        find_flag(filename, content)


def find_flag(filename, content):
    """
    匹配flag
    """
    content = content.replace('\x00', '')
    pattern = re.compile(r'ip.*(?:[0-9]{1,3}.*){3}[0-9]{1,3}')
    new_pattern = re.compile(r'ip:(?:[0-9]{1,3}\.){3}[0-9]{1,3}')
    result = re.findall(pattern, str(content))
    # print('pattern data', result)
    for item in result:
        item = item.replace('\x03', ':').replace('\x02', '.')
        new_result = re.findall(new_pattern, str(item))
        if len(new_result) > 0:
            write_data_to_result(filename, new_result[0])
            return False
    return False


def run_cmd(cmd_string, timeout=10):
    # https://blog.csdn.net/jiandanokok/article/details/103644902
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
            msg = "[Error]Called Error ： " + str(msg.decode(format))
        else:
            code = 0
            msg = str(msg.decode(format))
    except subprocess.TimeoutExpired:
        p.kill()
        p.terminate()
        # os.kill(p.pid, signal.CTRL_C_EVENT)
        # os.killpg(p.pid, signal.SIGTERM)
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
    with open('./tmp_file.ps1', 'w') as f:
        f.write(content)
    cmd_string = 'powershell.exe ./tmp_file.ps1'
    code, msg = run_cmd(cmd_string)
    return code, msg


def strip_not_null_strings(content):
    """
    去除无效的字符串
    """
    dense_content = content.replace('+', '').replace('\'', '').replace('`', '').replace('"', '').replace(' ', '').lower().strip()
    if dense_content.count('|out-null') \
        or dense_content.endswith('|(out-null)') \
        or dense_content.endswith('|(out-null);') \
        or dense_content.endswith('|.(out-null)'):
        index = content.rindex('|')
        return content[:index]
    return content


def is_ignore_line(line):
    """
    是否需要忽略该行
    """
    if line.lower().count('kill -name powershell') > 0:
        return True
    if line.lower().count('stop-process') > 0:
        return True
    if line.lower().count('downloaddata(') > 0:
        return True
    if line.lower().count('start-sleep') > 0:
        return True
    return False


def add_write_output(content):
    """
    增加一个输出
    """
    equal_symbol_index = content.index('=')
    variable_name = content[:equal_symbol_index].strip()
    if variable_name.count(' ') == 0 and variable_name.count('|') == 0:
        add_line = 'Write-Output ' + variable_name
        return content + '\n' + add_line
    else:
        pass  # todo: fix broken code
    return variable_name


def get_next_valid_line(content_list, cur_index):
    """
    获取不为空的下一行
    """
    for line in content_list[cur_index + 1:]:
        if line.strip() != '':
            return line.strip()
    return content_list[cur_index].strip()


def modify_else_if_to_if(content):
    """
    将elseif修改为if
    """
    # print('before', content)
    index = content.lower().index('elseif')
    elseif = content[index: index + len('elseif')]
    content = content.replace(elseif, '\nif')
    # print('after', content)
    return content


def modify_else_to_if(content):
    """
    将else修改为if
    """
    # print('before else: ', content)
    index = content.lower().index('else')
    elseif = content[index: index + len('else')]
    content = content.replace(elseif, '\nif($True)')
    # print('after else: ', content)
    return content


def get_whole_judge_condition(content_list, cur_index):
    """
    获取完整的判断条件
    eg:
    if (($OriginalImageBase -eq [Int64]$PEInfo.EffectivePEHandle) `
				-or ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.Size -eq 0))
    """
    result = [content_list[cur_index].strip()[:-1]]
    ignore_line_number = [cur_index]
    for line in content_list[cur_index + 1:]:
        if line.replace("'{'", '').strip().count('{') > 0:
        # if line.strip() == '{': # todo: if XX `\n YY {ZZ
            break
        result.append(line)
        ignore_line_number.append(cur_index + 1)
    else:
        print('debug:', content_list[cur_index])
    return '\n'.join(result), ignore_line_number


def modify_judge_condition(content, filename=None):
    """
    修改判断条件
    """
    # content = "if(($h.length -gt 3 ) -and ($h0 -eq 0xEF))\n{$h = h3()}"
    left_brackets_index = 0
    right_brackets_index = 0
    condition = []
    flag = False
    # print('before content: ', content)
    for _char in content[content.lower().index('if'):]:
        if _char == '(':
            left_brackets_index += 1
            flag = True
        if flag:
            condition.append(_char)
        if _char == ')':
            right_brackets_index += 1
        if left_brackets_index == right_brackets_index and left_brackets_index > 0:
            condition = ''.join(condition)
            new_content = content.replace(condition, '($True)')
            new_content_list = [item for item in new_content]
            if_index = new_content.lower().index('if')
            new_content_list.insert(if_index, '\n')  # if 前面添加一个换行
            # print('after content', ''.join(new_content_list))
            return ''.join(new_content_list)
    return content


def modify_content(content_list, filename):
    """
    对内容进行修改
    """
    result = []
    ignore_line_number = []  # 忽略的行数内容
    for index, line in enumerate(content_list):
        if index in ignore_line_number:
            continue
        dense_line = line.lower().replace(' ', '')  # 压缩后的数据

        if is_ignore_line(line):
            continue
        line = strip_not_null_strings(line)
        if dense_line.count('elseif(') > 0:
            line = modify_else_if_to_if(line)
        if dense_line.count('else{') > 0:
            line = modify_else_to_if(line)
        if dense_line.count('if(') > 0:
            if dense_line.endswith('`') == 0:
                line = modify_judge_condition(line, filename)
            else:
                whole_condition, ignore_line_number = get_whole_judge_condition(content_list, index)
                line = modify_judge_condition(whole_condition, filename)

        if dense_line.startswith('$') and dense_line.count('=') > 0 \
            and (get_next_valid_line(content_list, index) == '}' or get_next_valid_line(content_list, index).lower().startswith('if(')):
            line = add_write_output(line)

        result.append(line)
    return '\n'.join(result)


def handle_ps_command(filename, content):
    """
    处理ps命令行
    """
    base64_content = content.split(" ")[-1]
    base64_decode = base64.b64decode(base64_content.encode()).decode().replace("\x00", "")
    content = base64_decode[base64_decode.find("FromBase64String(") +
                            len("FromBase64String("):base64_decode.find("),[IO.Compression")]
    base64_flag = base64.b64decode(content.encode())
    zlib_data = zlib.decompress(base64_flag, -zlib.MAX_WBITS).decode()
    if find_flag(filename, zlib_data):
        return
    content_list = zlib_data.split('\n')
    new_content = modify_content(content_list, filename)
    last_files = set(glob.glob('./*'))
    code, msg = ps_decode(new_content)
    if find_flag(filename, msg):
        return
    find_flag_by_filename(last_files, filename)


def mock_execution(filename, content):
    """
    模拟执行
    """
    content_list = content.split('\n')
    new_content = modify_content(content_list, filename)
    last_files = set(glob.glob('./*'))
    code, msg = ps_decode(new_content)
    if find_flag(filename, msg):
        return
    find_flag_by_filename(last_files, filename)


def strip_iex_info(filename, content):
    """
    去除iex
    """
    iex_cmd_number, iex_info, min_index, max_index = get_iex_cmd_info(content)
    while iex_cmd_number >= 1:
        dense_content = content.replace(' ', '').replace('+', '').replace('\'', '').replace('`', '').replace("\"", '')
        status = False
        if iex_cmd_number >= 1:
            if min_index < index_offset:
                status, content = del_iex_cmd(content, iex_info, min_index, iex_cmd_number)
            elif max_index > len(dense_content) - index_offset:
                status, content = del_iex_cmd(content, iex_info, max_index, iex_cmd_number)
            if status:
                code, content = ps_decode(content)
                if code == 0:
                    iex_cmd_number, iex_info, min_index, max_index = get_iex_cmd_info(content)
                else:
                    break
            else:
                break
    return content


def get_success_md5():
    """
    成功的case
    """
    f = open('./result_v5.txt', 'r')
    line = f.readline()
    result = set()
    while line:
        result.add(line.split(',')[0])
        line = f.readline()
    return result


def debug_main():
    # is_need_add_new_line('', 1)
    # exit()
    # 统计代码
    base_path = './Second-Stage/*'
    # total_number = 0
    if os.path.exists(target_filename):
        os.remove(target_filename)
    success_data = get_success_md5()
    for filename in glob.glob(base_path):
        _file = filename.split('/')[-1]
        if _file in success_data:
            continue
        with open(filename, 'r', encoding='utf-8') as f:
            content = f.read()
        if 50000 > len(content) > 10000:
            content_list = content.split('\n')
            new_content = modify_content(content_list, filename)
            # print(filename)
            # print('###before###', content)
            # print('###after###', content)
            # for i in range(50):
            #     print('\n')


def debug_one_file():
    filename = './Second-Stage/ad36493c271c1aa04bf070534abb2e22b9d15271a56beb967b68aac7f67b05ca'
    if os.path.exists(target_filename):
        os.remove(target_filename)
    with open(filename, 'r', encoding='utf-8') as f:
        content = f.read()
    content_list = content.split('\n')
    new_content = modify_content(content_list, filename)
    exit()
    with open('./names.txt', 'a') as f:
        f.write(filename + '\n')
    print(filename)
    if content.startswith('powershell -NoP -NonI -W Hidden'):
        handle_ps_command(filename, content)
    else:
        content = strip_iex_info(filename, content)
        mock_execution(filename, content)


def main():
    # 统计代码
    base_path = './Second-Stage/*'
    debug_filename = './debug_filename.txt'
    if os.path.exists(target_filename):
        os.remove(target_filename)
    if os.path.exists(debug_filename):
        os.remove(debug_filename)
    for filename in glob.glob(base_path):
        with open(filename, 'r', encoding='utf-8') as f:
            content = f.read()

        with open(debug_filename, 'a') as f:
            f.write(filename + '\n')
        print(filename)
        if content.startswith('powershell -NoP -NonI -W Hidden'):
            handle_ps_command(filename, content)
        else:
            content = strip_iex_info(filename, content)
            mock_execution(filename, content)


if __name__ == '__main__':
    main()
    # debug_one_file()
    # debug_main()
