import os
import json
import re
from datetime import datetime
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

CONFIG = {
    "base_url": "https://source.android.com/docs/security/bulletin/asb-overview?hl=zh-cn",
    "patch_data_file": "android_patches.json",
    "latest_patch_file": "latest_patch.txt",  # 最新补丁记录文件
    "processed_file": "processed_urls.json",
    "cve_details_dir": "cve_details",  # 存储CVE详细信息的目录
}

# 确保CVE详细信息目录存在
os.makedirs(CONFIG["cve_details_dir"], exist_ok=True)


def extract_patch_number(url):
    """从URL中提取补丁编号（YYYY-MM-DD格式）"""
    match = re.search(r"/(\d{4}-\d{2}-\d{2})\?hl=zh-cn", url)
    return match.group(1) if match else None


def load_processed_urls():
    """加载已处理的URL记录"""
    if os.path.exists(CONFIG["processed_file"]):
        with open(CONFIG["processed_file"], "r") as f:
            return json.load(f).get("urls", [])
    return []


def save_processed_urls(urls):
    """保存已处理的URL"""
    data = {"last_update": datetime.now().isoformat(), "urls": urls}
    with open(CONFIG["processed_file"], "w") as f:
        json.dump(data, f, indent=2)


def fetch_bulletin_links():
    """获取所有中文公告链接（带增量检查）"""
    processed = load_processed_urls()
    try:
        response = requests.get(CONFIG["base_url"], timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")

        new_bulletins = []
        for row in soup.find("table").find_all("tr")[1:]:
            cols = row.find_all("td")
            if len(cols) < 4:
                continue

            zh_link = next(
                (
                    urljoin(CONFIG["base_url"], a["href"])
                    for a in cols[1].find_all("a")
                    if "hl=zh-cn" in a["href"]
                ),
                None,
            )

            if zh_link and zh_link not in processed:
                if patch := extract_patch_number(zh_link):
                    new_bulletins.append(
                        {
                            "url": zh_link,
                            "security_patch": patch,
                            "discovered": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        }
                    )

        return new_bulletins
    except Exception as e:
        print(f"获取公告失败: {str(e)}")
        return []


def update_latest_patch(patches):
    """更新最新补丁记录"""
    if not patches:
        return None

    # 提取所有补丁日期并找到最新
    latest = max(patches, key=lambda x: x["security_patch"])
    latest_str = f"{latest['security_patch']} | {latest['url']}"

    # 输出到终端
    print(f"\n最新安全补丁: {latest['security_patch']}")
    print(f"详细信息地址: {latest['url']}\n")

    # 保存到文件
    with open(CONFIG["latest_patch_file"], "w") as f:
        f.write(latest_str)

    return latest["security_patch"]


def get_latest_patch(data):
    """从数据中获取最新补丁"""
    if not data:
        return None
    return max(data, key=lambda x: x["security_patch"])


def fetch_cve_details(patch_info):
    """获取补丁的CVE详细信息"""
    try:
        print(f"正在获取补丁 {patch_info['security_patch']} 的CVE详细信息...")
        
        # 检查是否已经获取过该补丁的CVE信息
        cve_file = os.path.join(CONFIG["cve_details_dir"], f"cve_{patch_info['security_patch']}.json")
        if os.path.exists(cve_file):
            print(f"已存在CVE信息文件: {cve_file}，跳过获取")
            return
            
        # 获取公告详情页面
        response = requests.get(patch_info["url"], timeout=15)
        response.raise_for_status()
        
        # 解析CVE信息
        soup = BeautifulSoup(response.text, "html.parser")
        cve_count = 0
        cve_details = []
        
        # 查找所有包含CVE的表格
        for table in soup.find_all("table"):
            headers = [th.get_text(strip=True) for th in table.find_all("th")]
            if any("CVE" in header for header in headers):
                # 找到CVE列的索引
                cve_index = next((i for i, h in enumerate(headers) if "CVE" in h), None)
                if cve_index is not None:
                    for row in table.find_all("tr")[1:]:  # 跳过表头
                        cells = row.find_all("td")
                        if len(cells) > cve_index:
                            cve_id = cells[cve_index].get_text(strip=True)
                            # 收集其他相关信息
                            cve_info = {
                                "cve_id": cve_id,
                                "details": {}
                            }
                            for i, header in enumerate(headers):
                                if i < len(cells) and i != cve_index:
                                    cve_info["details"][header] = cells[i].get_text(strip=True)
                            cve_details.append(cve_info)
                cve_count += len(table.find_all("tr")) - 1  # 减去表头
        
        # 准备保存的数据
        save_data = {
            "security_patch": patch_info['security_patch'],
            "url": patch_info['url'],
            "cve_count": cve_count,
            "discovered": patch_info['discovered'],
            "fetched_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "cve_details": cve_details
        }
        
        # 保存到文件
        with open(cve_file, 'w', encoding='utf-8') as f:
            json.dump(save_data, f, ensure_ascii=False, indent=2)
        print(f"CVE详细信息已保存到文件: {cve_file}")
        
        return cve_count
    except Exception as e:
        print(f"获取CVE详细信息失败: {str(e)}")
        return None


def check_missing_cve_details(patches):
    """检查是否有缺失的CVE详细信息，并获取缺失的信息"""
    print("检查是否有缺失的CVE详细信息...")
    missing_count = 0
    
    for patch in patches:
        cve_file = os.path.join(CONFIG["cve_details_dir"], f"cve_{patch['security_patch']}.json")
        if not os.path.exists(cve_file):
            print(f"发现缺失的CVE信息: {patch['security_patch']}")
            fetch_cve_details(patch)
            missing_count += 1
    
    if missing_count == 0:
        print("所有补丁的CVE详细信息已完整")
    else:
        print(f"已获取 {missing_count} 个缺失的CVE详细信息")
    
    return missing_count


def main():
    # 加载现有数据
    existing_data = []
    if os.path.exists(CONFIG["patch_data_file"]):
        with open(CONFIG["patch_data_file"], "r") as f:
            existing_data = json.load(f)

    # 增量抓取
    new_bulletins = fetch_bulletin_links()

    if new_bulletins:
        # 合并新数据（去重）
        existing_urls = {item["url"] for item in existing_data}
        new_items = [item for item in new_bulletins if item["url"] not in existing_urls]
        updated_data = existing_data + new_items

        # 保存数据
        with open(CONFIG["patch_data_file"], "w") as f:
            json.dump(updated_data, f, ensure_ascii=False, indent=2)

        # 更新已处理URL
        save_processed_urls([b["url"] for b in new_bulletins] + load_processed_urls())
        data_source = updated_data
        print(f"发现 {len(new_items)} 个新补丁")
        
        # 为新发现的补丁获取CVE信息
        for patch in new_items:
            fetch_cve_details(patch)
    else:
        data_source = existing_data
        print("没有发现新公告")
    
    # 检查并获取所有补丁的CVE详细信息
    check_missing_cve_details(data_source)

    # 始终显示最新补丁
    if latest := get_latest_patch(data_source):
        print(f"\n当前最新安全补丁: {latest['security_patch']}")
        print(f"详细信息地址: {latest['url']}")

        # 更新最新补丁记录文件
        with open(CONFIG["latest_patch_file"], "w") as f:
            f.write(f"{latest['security_patch']} | {latest['url']}")
            
        # 确保最新补丁的CVE信息已获取
        cve_file = os.path.join(CONFIG["cve_details_dir"], f"cve_{latest['security_patch']}.json")
        if not os.path.exists(cve_file):
            fetch_cve_details(latest)
    else:
        print("警告：尚未记录任何安全补丁信息")


if __name__ == "__main__":
    main()
