#!/usr/bin/env python3
"""网络钓鱼事件响应 Agent - 分析钓鱼邮件并自动化响应措施。"""

import json
import re
import email
import hashlib
import logging
import argparse
from email import policy
from datetime import datetime

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def parse_email_file(eml_path):
    """解析 EML 文件并提取邮件头和正文信息。"""
    with open(eml_path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=policy.default)
    parsed = {
        "subject": msg["Subject"],
        "from": msg["From"],
        "to": msg["To"],
        "date": msg["Date"],
        "message_id": msg["Message-ID"],
        "return_path": msg["Return-Path"],
        "reply_to": msg["Reply-To"],
        "received_headers": msg.get_all("Received", []),
        "authentication_results": msg.get("Authentication-Results", ""),
        "spf": "",
        "dkim": "",
        "dmarc": "",
    }
    auth_results = parsed["authentication_results"]
    if "spf=pass" in auth_results:
        parsed["spf"] = "pass"
    elif "spf=fail" in auth_results:
        parsed["spf"] = "fail"
    if "dkim=pass" in auth_results:
        parsed["dkim"] = "pass"
    elif "dkim=fail" in auth_results:
        parsed["dkim"] = "fail"
    if "dmarc=pass" in auth_results:
        parsed["dmarc"] = "pass"
    elif "dmarc=fail" in auth_results:
        parsed["dmarc"] = "fail"

    logger.info("已解析邮件：主题='%s' 发件人='%s'", parsed["subject"], parsed["from"])
    return parsed, msg


def extract_urls(msg):
    """从邮件正文中提取所有 URL。"""
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ("text/plain", "text/html"):
                body += part.get_content()
    else:
        body = msg.get_content()
    urls = re.findall(r'https?://[^\s"\'<>]+', body)
    unique_urls = list(set(urls))
    logger.info("提取了 %d 个唯一 URL", len(unique_urls))
    return unique_urls


def extract_attachments(msg):
    """提取并计算邮件附件的哈希。"""
    attachments = []
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            filename = part.get_filename()
            content = part.get_payload(decode=True)
            if content:
                sha256 = hashlib.sha256(content).hexdigest()
                md5 = hashlib.md5(content).hexdigest()
                attachments.append({
                    "filename": filename,
                    "content_type": part.get_content_type(),
                    "size": len(content),
                    "sha256": sha256,
                    "md5": md5,
                })
                logger.info("附件: %s（SHA256: %s）", filename, sha256[:16])
    return attachments


def check_url_virustotal(url, api_key):
    """在 VirusTotal 上检查 URL 信誉。"""
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": api_key}
    resp = requests.get(vt_url, headers=headers, timeout=30)
    if resp.status_code == 200:
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "url": url,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
        }
    return {"url": url, "error": resp.status_code}


def check_url_urlscan(url):
    """将 URL 提交到 urlscan.io 进行分析。"""
    resp = requests.post(
        "https://urlscan.io/api/v1/scan/",
        json={"url": url, "visibility": "private"},
        headers={"Content-Type": "application/json"},
        timeout=30,
    )
    if resp.status_code == 200:
        return resp.json()
    return {"url": url, "error": resp.status_code}


def check_hash_virustotal(file_hash, api_key):
    """在 VirusTotal 上检查文件哈希信誉。"""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    resp = requests.get(url, headers=headers, timeout=30)
    if resp.status_code == 200:
        attrs = resp.json()["data"]["attributes"]
        return {
            "hash": file_hash,
            "malicious": attrs["last_analysis_stats"].get("malicious", 0),
            "threat_name": attrs.get("popular_threat_classification", {}).get("suggested_threat_label", ""),
        }
    return {"hash": file_hash, "status": "not_found"}


def assess_phishing_severity(parsed_email, url_results, attachment_results):
    """评估钓鱼邮件的整体严重性。"""
    severity = "低"
    indicators = []
    if parsed_email.get("spf") == "fail":
        indicators.append("SPF 验证失败")
        severity = "中"
    if parsed_email.get("dkim") == "fail":
        indicators.append("DKIM 验证失败")
        severity = "中"
    if parsed_email.get("dmarc") == "fail":
        indicators.append("DMARC 验证失败")
        severity = "中"
    for url_result in url_results:
        if url_result.get("malicious", 0) > 0:
            indicators.append(f"恶意 URL: {url_result['url'][:50]}")
            severity = "严重"
    for att_result in attachment_results:
        if att_result.get("malicious", 0) > 0:
            indicators.append(f"恶意附件: {att_result['hash'][:16]}")
            severity = "严重"
    return {"severity": severity, "indicators": indicators}


def generate_phishing_report(parsed_email, urls, attachments, url_results, att_results, assessment):
    """生成网络钓鱼事件响应报告。"""
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "email_headers": parsed_email,
        "urls_found": urls,
        "attachments": attachments,
        "url_analysis": url_results,
        "attachment_analysis": att_results,
        "severity_assessment": assessment,
    }
    print(f"钓鱼 IR 报告 - 严重性: {assessment['severity']}")
    print(f"URL: {len(urls)} 个，附件: {len(attachments)} 个，指标: {len(assessment['indicators'])} 个")
    return report


def main():
    parser = argparse.ArgumentParser(description="网络钓鱼事件响应 Agent")
    parser.add_argument("--eml", required=True, help="EML 文件路径")
    parser.add_argument("--vt-key", help="VirusTotal API 密钥")
    parser.add_argument("--output", default="phishing_ir_report.json")
    args = parser.parse_args()

    parsed, msg = parse_email_file(args.eml)
    urls = extract_urls(msg)
    attachments = extract_attachments(msg)

    url_results = []
    if args.vt_key:
        for url in urls[:10]:
            url_results.append(check_url_virustotal(url, args.vt_key))

    att_results = []
    if args.vt_key:
        for att in attachments:
            att_results.append(check_hash_virustotal(att["sha256"], args.vt_key))

    assessment = assess_phishing_severity(parsed, url_results, att_results)
    report = generate_phishing_report(parsed, urls, attachments, url_results, att_results, assessment)

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("报告已保存到 %s", args.output)


if __name__ == "__main__":
    main()
