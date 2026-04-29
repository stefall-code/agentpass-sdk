#!/usr/bin/env python3
"""
分析漏检样本 - 查看为什么有些攻击没有被检测到
"""
import json
from collections import Counter


def main():
    # 加载结果
    with open("prompt_defense_results.json", "r", encoding="utf-8") as f:
        data = json.load(f)
    
    results = data["results"]
    
    # 找出漏检样本
    missed = [r for r in results if r["true_label"] == "attack" and r["pred_label"] == "normal"]
    
    print("="*80)
    print(f"漏检样本分析（共 {len(missed)} 个）")
    print("="*80)
    
    # 按攻击类型统计
    type_counts = Counter(r["true_type"] for r in missed)
    print("\n【漏检样本按攻击类型分布】")
    for attack_type, count in type_counts.most_common():
        print(f"  {attack_type:20s}: {count}")
    
    # 查看各类漏检样本示例
    print("\n【漏检样本示例】")
    for attack_type in type_counts:
        samples = [r for r in missed if r["true_type"] == attack_type]
        print(f"\n--- {attack_type} ---")
        for i, sample in enumerate(samples[:5]):
            print(f"  {i+1}. {sample['prompt']}")
            print(f"     预测风险分: {sample['risk_score']}")
            print(f"     原因: {sample['reason']}")
    
    # 查看误报样本（虽然这次没有）
    false_positives = [r for r in results if r["true_label"] == "normal" and r["pred_label"] == "attack"]
    print(f"\n【误报样本数量】: {len(false_positives)}")
    
    # 风险分数分布
    print("\n【漏检样本风险分数分布】")
    risk_bins = [0, 0.1, 0.2, 0.3, 0.4, 0.5, 1.0]
    for i in range(len(risk_bins)-1):
        low, high = risk_bins[i], risk_bins[i+1]
        count = sum(1 for r in missed if low <= r["risk_score"] < high)
        print(f"  [{low:.1f} - {high:.1f}): {count}")


if __name__ == "__main__":
    main()
