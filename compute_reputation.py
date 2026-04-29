"""
手动计算声誉分数的脚本，绕过 agentpass 依赖
"""
import sys
sys.path.insert(0, '.')

from app.services.reputation_service import ReputationEngine

# 直接计算所有 agent 的声誉分数
try:
    engine = ReputationEngine()
    engine.recompute_all()
    print("声誉分数计算完成！")
except Exception as e:
    print(f"计算过程中出现错误: {e}")
    import traceback
    traceback.print_exc()