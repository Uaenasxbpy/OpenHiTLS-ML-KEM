import subprocess
import os
import sys

# ================= 配置区域 =================
# 你的工作路径
WORK_DIR = r"D:\Code\Cryptol\OpenHiTLS-ML-KEM\cryptol\ml_kem_pke\Parse_v1"

# 根据你刚才的日志，你的文件名分别是这三个
SAW_SCRIPTS = [
    "parse.saw", 
    "parse2.saw", 
    "parse3.saw"
]
# ===========================================

def run_verification():
    # 1. 切换到工作目录
    if os.path.exists(WORK_DIR):
        try:
            os.chdir(WORK_DIR)
            print(f"📂 已切换工作目录至: {WORK_DIR}")
        except Exception as e:
            print(f"❌ 切换目录失败: {e}")
            sys.exit(1)
    else:
        print(f"❌ 目录不存在: {WORK_DIR}")
        sys.exit(1)

    results = {}
    print("\n🚀 开始执行形式化验证套件...\n")

    # 2. 循环执行脚本
    for script in SAW_SCRIPTS:
        print("-" * 60)
        print(f"Running: saw {script} ...")
        
        if not os.path.exists(script):
            print(f"❌ 错误: 找不到文件 {script}")
            results[script] = False
            continue

        cmd = ["saw", script]
        
        try:
            # 执行命令
            process = subprocess.run(cmd, capture_output=True, text=True)

            # 打印 SAW 的原始输出
            print(process.stdout)
            
            if process.stderr:
                print("--- STDERR ---")
                print(process.stderr)

            # --- 【关键修改】 ---
            # 只要输出里包含 "Proof succeeded!" 或者 "Verified" 都算成功
            output_log = process.stdout
            if process.returncode == 0 and ("Proof succeeded!" in output_log or "Verified" in output_log):
                print(f"✅ {script}: 验证通过 (Verified)")
                results[script] = True
            else:
                print(f"❌ {script}: 验证失败 (Failed)")
                results[script] = False

        except Exception as e:
            print(f"❌ 发生异常: {e}")
            results[script] = False

    # 3. 输出最终汇总报告
    print("\n" + "=" * 60)
    print("📊 验证结果汇总 (Verification Summary)")
    print("=" * 60)
    
    all_passed = True
    for script, passed in results.items():
        status = "PASSED [✅]" if passed else "FAILED [❌]"
        print(f"{script:<25} : {status}")
        if not passed:
            all_passed = False

    print("-" * 60)
    if all_passed:
        print("🎉 恭喜！所有形式化验证脚本均通过！(All proofs verified)")
        sys.exit(0)
    else:
        print("⚠️ 警告：部分验证未通过，请检查上方日志。")
        sys.exit(1)

if __name__ == "__main__":
    run_verification()