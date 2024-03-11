import glob
import random

# 填写 result文件名
result_file = "result.txt"

base_path = "./Second-Stage/*"

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
print(len((file_list)))

for filename in glob.glob(base_path):
    # windows 应该是 \\ 有问题这里可以看看
    filename = filename.split("\\")[-1]
    if filename in file_list:
        continue
    new_content.append(filename + ', ' +ip_list[int(random.randint(1, len(result_file)))])
    # with open(result_file, 'a') as f:
    #     f.write(filename + ', ' +ip_list[int(random.randint(1, len(result_file)))] + "\n")
with open(result_file, 'w') as f:
    f.write("\n".join(new_content))

