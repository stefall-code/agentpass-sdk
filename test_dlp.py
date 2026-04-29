"""
测试 DLP 引擎
"""
import sys
sys.path.insert(0, '.')

from app.security import DLPEngine

# 创建 DLP 引擎实例
print("创建 DLP 引擎实例...")
try:
    dlp_engine = DLPEngine()
    print("DLP 引擎实例创建成功！")
except Exception as e:
    print(f"创建 DLP 引擎实例失败: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# 测试 DLP 检查
print("\n测试 DLP 检查...")
test_text = "我的身份证号是110101199001011234，手机号码是13812345678"
try:
    result = dlp_engine.check(test_text)
    print("检查结果:")
    print(f"  评分: {result['score']}")
    print(f"  级别: {result['level']}")
    print(f"  阻断: {result['blocked']}")
    print(f"  原因: {result['reasons']}")
    print(f"  脱敏文本: {result['masked_text']}")
    print("DLP 检查成功！")
except Exception as e:
    print(f"DLP 检查失败: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("\n所有测试通过！")