#!/usr/bin/env python3
"""
安全评估报告生成器

根据交互式问答收集的安全评估数据，生成结构化的 Markdown 安全评估报告。

用法:
    python generate_security_report.py

运行后按提示输入评估信息，脚本将生成报告文件并输出路径。
也可通过命令行参数以非交互模式使用:
    python generate_security_report.py --target "目标系统" --type web --findings findings.json --output report.md
"""

import json
import sys
import os
from datetime import datetime
from pathlib import Path

RISK_LEVELS = {
    (13, 15): ("严重", "RED"),
    (10, 12): ("高", "ORANGE"),
    (7, 9): ("中", "YELLOW"),
    (4, 6): ("低", "BLUE"),
    (3, 3): ("信息", "GREEN"),
}

SYSTEM_TYPES = {
    "web": "Web 应用",
    "network": "网络基础设施",
    "mobile": "移动应用",
    "cloud": "云环境",
    "general": "通用系统",
}


def calculate_risk_level(impact, exploitability, scope):
    """根据三个维度计算综合风险等级。"""
    total = impact + exploitability + scope
    for (low, high), (level, color) in RISK_LEVELS.items():
        if low <= total <= high:
            return level, color, total
    return "未知", "GRAY", total


def generate_report_md(target_name, system_type, assessor, findings):
    """生成 Markdown 格式的安全评估报告。"""
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    type_label = SYSTEM_TYPES.get(system_type, system_type)

    # 统计风险分布
    risk_counts = {"严重": 0, "高": 0, "中": 0, "低": 0, "信息": 0}
    for f in findings:
        level = f.get("risk_level", "信息")
        if level in risk_counts:
            risk_counts[level] += 1

    total_findings = len(findings)

    lines = []
    lines.append(f"# 安全评估报告")
    lines.append("")
    lines.append(f"| 项目 | 内容 |")
    lines.append(f"|------|------|")
    lines.append(f"| 评估目标 | {target_name} |")
    lines.append(f"| 系统类型 | {type_label} |")
    lines.append(f"| 评估人员 | {assessor} |")
    lines.append(f"| 评估时间 | {now} |")
    lines.append(f"| 发现总数 | {total_findings} |")
    lines.append("")

    # 风险概览
    lines.append("## 风险概览")
    lines.append("")
    lines.append("| 风险等级 | 数量 |")
    lines.append("|----------|------|")
    for level in ["严重", "高", "中", "低", "信息"]:
        lines.append(f"| {level} | {risk_counts[level]} |")
    lines.append("")

    # 详细发现
    if findings:
        lines.append("## 详细发现")
        lines.append("")

        # 按风险等级排序
        priority_order = {"严重": 0, "高": 1, "中": 2, "低": 3, "信息": 4}
        sorted_findings = sorted(
            findings,
            key=lambda f: priority_order.get(f.get("risk_level", "信息"), 5),
        )

        for i, f in enumerate(sorted_findings, 1):
            lines.append(f"### 发现 #{i}: {f.get('title', '未命名风险')}")
            lines.append("")
            lines.append(f"- **风险等级**: {f.get('risk_level', '未评级')}")
            lines.append(f"- **影响程度**: {f.get('impact', 'N/A')}/5")
            lines.append(f"- **利用难度**: {f.get('exploitability', 'N/A')}/5")
            lines.append(f"- **影响范围**: {f.get('scope', 'N/A')}/5")
            lines.append(f"- **风险总分**: {f.get('total_score', 'N/A')}")
            lines.append("")
            if f.get("description"):
                lines.append(f"**描述**:")
                lines.append("")
                lines.append(f.get("description"))
                lines.append("")
            if f.get("evidence"):
                lines.append(f"**证据**:")
                lines.append("")
                lines.append(f"```")
                lines.append(f.get("evidence"))
                lines.append(f"```")
                lines.append("")
            if f.get("recommendation"):
                lines.append(f"**修复建议**:")
                lines.append("")
                lines.append(f.get("recommendation"))
                lines.append("")
            if f.get("references"):
                lines.append(f"**参考**:")
                lines.append(f.get("references"))
                lines.append("")
            lines.append("---")
            lines.append("")

    # 总结建议
    lines.append("## 总结与建议")
    lines.append("")
    if risk_counts["严重"] > 0 or risk_counts["高"] > 0:
        lines.append(f"本次评估发现 **{risk_counts['严重']}** 个严重风险和 **{risk_counts['高']}** 个高风险，")
        lines.append("建议立即启动应急修复流程，优先处理严重和高风险项。")
        lines.append("")
        lines.append("### 短期行动项 (7 天内)")
        lines.append("1. 修复所有严重级别漏洞")
        lines.append("2. 对高风险项实施临时缓解措施")
        lines.append("3. 加强监控和告警覆盖")
    elif risk_counts["中"] > 0:
        lines.append(f"本次评估发现 **{risk_counts['中']}** 个中风险，未发现严重或高风险。")
        lines.append("建议在 30 天内完成修复，并持续监控风险变化。")
    else:
        lines.append("本次评估未发现严重安全风险，整体安全状况良好。")
        lines.append("建议保持定期安全评估和安全基线检查。")

    lines.append("")
    lines.append("### 长期改进建议")
    lines.append("1. 建立定期安全评估机制（每季度）")
    lines.append("2. 实施安全开发生命周期 (SDLC)")
    lines.append("3. 部署自动化安全扫描工具")
    lines.append("4. 开展安全意识培训")
    lines.append("5. 完善应急响应预案并定期演练")
    lines.append("")
    lines.append("---")
    lines.append(f"*本报告由安全评估报告生成器自动生成于 {now}*")

    return "\n".join(lines)


def interactive_mode():
    """交互式收集评估信息并生成报告。"""
    print("=" * 60)
    print("  网络信息安全评估报告生成器")
    print("=" * 60)
    print()

    target_name = input("请输入评估目标名称: ").strip()
    if not target_name:
        target_name = "未命名目标"

    print("\n可选系统类型:")
    for k, v in SYSTEM_TYPES.items():
        print(f"  {k} - {v}")
    system_type = input("\n请输入系统类型 (默认 general): ").strip().lower() or "general"

    assessor = input("请输入评估人员名称: ").strip()
    if not assessor:
        assessor = "匿名"

    findings = []
    print("\n--- 安全发现录入 (输入空标题结束) ---")

    while True:
        print(f"\n[发现 #{len(findings) + 1}]")
        title = input("风险标题: ").strip()
        if not title:
            break

        description = input("风险描述: ").strip()
        evidence = input("证据/示例 (可选): ").strip()

        print("\n影响程度 (1-5, 5=灾难性): ", end="")
        try:
            impact = int(input().strip())
        except ValueError:
            impact = 3

        print("利用难度 (1-5, 5=极易): ", end="")
        try:
            exploitability = int(input().strip())
        except ValueError:
            exploitability = 3

        print("影响范围 (1-5, 5=全局): ", end="")
        try:
            scope = int(input().strip())
        except ValueError:
            scope = 3

        risk_level, _, total_score = calculate_risk_level(impact, exploitability, scope)

        recommendation = input("修复建议: ").strip()
        references = input("参考链接 (可选): ").strip()

        findings.append({
            "title": title,
            "description": description,
            "evidence": evidence,
            "impact": impact,
            "exploitability": exploitability,
            "scope": scope,
            "risk_level": risk_level,
            "total_score": total_score,
            "recommendation": recommendation,
            "references": references,
        })

        print(f"  -> 风险评级: {risk_level} (总分: {total_score})")

    if not findings:
        print("\n未录入任何安全发现。")
        return

    report = generate_report_md(target_name, system_type, assessor, findings)

    output_dir = Path.cwd()
    filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    output_path = output_dir / filename

    output_path.write_text(report, encoding="utf-8")
    print(f"\n报告已生成: {output_path}")
    print(f"共记录 {len(findings)} 项安全发现。")


def cli_mode(args):
    """命令行参数模式。"""
    import argparse

    parser = argparse.ArgumentParser(description="安全评估报告生成器")
    parser.add_argument("--target", required=True, help="评估目标名称")
    parser.add_argument("--type", default="general", help="系统类型")
    parser.add_argument("--assessor", default="匿名", help="评估人员")
    parser.add_argument("--findings", required=True, help="发现数据 JSON 文件路径")
    parser.add_argument("--output", help="输出报告文件路径")

    parsed = parser.parse_args(args)

    with open(parsed.findings, "r", encoding="utf-8") as f:
        findings_data = json.load(f)

    findings = findings_data if isinstance(findings_data, list) else findings_data.get("findings", [])

    # 计算风险等级
    for finding in findings:
        if "risk_level" not in finding:
            impact = finding.get("impact", 3)
            exploitability = finding.get("exploitability", 3)
            scope = finding.get("scope", 3)
            level, _, total = calculate_risk_level(impact, exploitability, scope)
            finding["risk_level"] = level
            finding["total_score"] = total

    report = generate_report_md(parsed.target, parsed.type, parsed.assessor, findings)

    if parsed.output:
        output_path = Path(parsed.output)
    else:
        output_path = Path.cwd() / f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"

    output_path.write_text(report, encoding="utf-8")
    print(f"报告已生成: {output_path}")


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--target":
        cli_mode(sys.argv[1:])
    else:
        interactive_mode()


if __name__ == "__main__":
    main()
