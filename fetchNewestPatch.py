import requests
import re
import json
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from datetime import datetime

def fetch_latest_android_patch():
    """直接从安卓安全公告网站爬取最新的补丁版本信息"""
    base_url = "https://source.android.com/docs/security/bulletin/asb-overview?hl=zh-cn"
    
    try:
        # 获取安全公告概览页面
        print("正在获取安卓安全公告列表...")
        response = requests.get(base_url, timeout=10)
        response.raise_for_status()
        
        # 解析HTML
        soup = BeautifulSoup(response.text, "html.parser")
        
        # 查找表格中的第一个有效行（最新的安全公告）
        latest_bulletin = None
        
        for row in soup.find("table").find_all("tr")[1:]:  # 跳过表头
            cols = row.find_all("td")
            if len(cols) < 4:
                continue
                
            # 查找中文链接
            zh_link = next(
                (
                    urljoin(base_url, a["href"])
                    for a in cols[1].find_all("a")
                    if "hl=zh-cn" in a["href"]
                ),
                None,
            )
            
            if zh_link:
                # 从URL中提取补丁日期
                match = re.search(r"/(\d{4}-\d{2}-\d{2})\?hl=zh-cn", zh_link)
                if match:
                    patch_date = match.group(1)
                    latest_bulletin = {
                        "security_patch": patch_date,
                        "url": zh_link,
                        "discovered": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                    break  # 找到第一个（最新的）就退出
        
        if latest_bulletin:
            # 获取公告详情页面以获取更多信息
            print(f"正在获取最新补丁 {latest_bulletin['security_patch']} 的详细信息...")
            detail_response = requests.get(latest_bulletin["url"], timeout=15)
            detail_response.raise_for_status()
            
            # 解析CVE数量和详细信息
            detail_soup = BeautifulSoup(detail_response.text, "html.parser")
            cve_count = 0
            cve_details = []
            
            # 计算所有表格中包含"CVE"的行数并提取CVE详情
            for table in detail_soup.find_all("table"):
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
            
            latest_bulletin["cve_count"] = cve_count
            latest_bulletin["cve_details"] = cve_details
            
            # 保存CVE详细信息到文件
            save_cve_details(latest_bulletin)
            
            return latest_bulletin
            
        else:
            print("未找到任何安全公告")
            return None
            
    except Exception as e:
        print(f"获取最新补丁信息失败: {str(e)}")
        return None

def save_cve_details(patch_info):
    """保存CVE详细信息到文件"""
    if not patch_info or "cve_details" not in patch_info:
        return
    
    # 创建文件名：cve_details_YYYY-MM-DD.json
    filename = f"cve_details_{patch_info['security_patch']}.json"
    
    # 准备保存的数据
    save_data = {
        "security_patch": patch_info['security_patch'],
        "url": patch_info['url'],
        "cve_count": patch_info['cve_count'],
        "discovered": patch_info['discovered'],
        "cve_details": patch_info['cve_details']
    }
    
    # 保存到文件
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(save_data, f, ensure_ascii=False, indent=2)
        print(f"CVE详细信息已保存到文件: {filename}")
    except Exception as e:
        print(f"保存CVE详细信息失败: {str(e)}")

def display_patch_info(patch_info):
    """格式化显示补丁信息"""
    if not patch_info:
        print("未能获取到最新的安卓安全补丁信息")
        return
    
    print("\n" + "="*50)
    print("安卓最新安全补丁信息")
    print("="*50)
    print(f"补丁版本: {patch_info['security_patch']}")
    print(f"发布地址: {patch_info['url']}")
    
    if "cve_count" in patch_info:
        print(f"包含CVE数量: {patch_info['cve_count']}")
    
    print(f"获取时间: {patch_info['discovered']}")
    
    if "cve_details" in patch_info and patch_info["cve_details"]:
        print(f"CVE详细信息已保存到文件: cve_details_{patch_info['security_patch']}.json")
    
    print("="*50)

def main():
    """主函数"""
    print("开始获取安卓最新安全补丁信息...")
    latest_patch = fetch_latest_android_patch()
    display_patch_info(latest_patch)

if __name__ == "__main__":
    main()