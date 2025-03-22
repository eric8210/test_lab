from flask import Flask, render_template, request, redirect, url_for, flash
import pandas as pd
import os
from datetime import datetime, timedelta
import logging
from pathlib import Path

# 初始化Flask应用
app = Flask(__name__)
app.secret_key = os.urandom(24)  # 用于flash消息加密

# 配置路径
BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / 'data'
INVENTORY_PATH = DATA_DIR / 'inventory.csv'
REPORTS_DIR = DATA_DIR / 'reports'

# 确保目录存在
DATA_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# 日志配置
logging.basicConfig(
    filename=DATA_DIR / 'webapp.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def validate_cpe(cpe_str):
    """基础CPE格式验证"""
    return cpe_str.startswith('cpe:/') and len(cpe_str.split(':')) >= 5

@app.route('/')
def index():
    """系统主页"""
    return render_template('index.html')

@app.route('/inventory', methods=['GET', 'POST'])
def manage_inventory():
    try:
        # 确保文件存在时读取，否则创建空DataFrame
        if INVENTORY_PATH.exists():
            df = pd.read_csv(INVENTORY_PATH, keep_default_na=False)
            app.logger.info(f"成功加载{len(df)}条资产记录")  # 添加日志
        else:
            df = pd.DataFrame(columns=['vendor', 'os_version', 'cpe'])
            app.logger.warning("未找到inventory.csv，已创建空数据框")

        # 处理删除操作
        if 'delete' in request.form:
            index = int(request.form['index'])
            if 0 <= index < len(df):
                df = df.drop(index).reset_index(drop=True)
                df.to_csv(INVENTORY_PATH, index=False)
                flash('成功删除资产记录', 'success')
            else:
                flash('无效的删除索引', 'danger')

        # 处理新增/编辑操作
        if 'submit' in request.form:
            form_data = {
                'vendor': request.form['vendor'].strip(),
                'os_version': request.form['os_version'].strip(),
                'cpe': request.form['cpe'].strip()
            }

            # 数据验证
            if not all(form_data.values()):
                flash('所有字段必须填写', 'danger')
            elif not validate_cpe(form_data['cpe']):
                flash('CPE格式无效（必须以cpe:/开头且包含足够字段）', 'danger')
            else:
                mode = request.form['mode']
                if mode == 'add':
                    df = pd.concat([df, pd.DataFrame([form_data])], ignore_index=True)
                    flash('成功添加新资产', 'success')
                elif mode == 'edit':
                    index = int(request.form['index'])
                    if 0 <= index < len(df):
                        df.loc[index] = form_data
                        flash('成功更新资产信息', 'success')
                    else:
                        flash('无效的编辑索引', 'danger')
                df.to_csv(INVENTORY_PATH, index=False)

        return render_template('inventory.html', 
                             data=df.to_dict('records'),
                             timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    except Exception as e:
        logging.error(f"资产管理操作失败: {str(e)}", exc_info=True)
        flash('系统处理请求时发生错误', 'danger')
        return redirect(url_for('index'))


@app.route('/report')

def show_report():
    try:
        report_date = datetime.now().strftime("%Y-%m-%d")
        report_path = REPORTS_DIR / f'cve_report_{report_date}.csv'
        
        if not report_path.exists():
            flash('今日报告尚未生成', 'warning')
            return render_template('report.html', data=[])

        df = pd.read_csv(report_path, parse_dates=['published', 'lastModified'])
        cutoff_date = datetime.now() - timedelta(days=7)
        filtered_df = df[
            (df['published'] >= cutoff_date) |
            (df['lastModified'] >= cutoff_date)
        ]

        # 关键修复：仅在数据存在时处理
        if not filtered_df.empty:
            filtered_df['published'] = filtered_df['published'].dt.strftime('%Y-%m-%d %H:%M')
            filtered_df['lastModified'] = filtered_df['lastModified'].dt.strftime('%Y-%m-%d %H:%M')
        else:
            app.logger.info("无符合时间条件的报告数据")

        return render_template('report.html',
                             data=filtered_df.to_dict('records'),
                             report_date=report_date)
    except Exception as e:
        app.logger.error(f"报告加载失败: {str(e)}", exc_info=True)
        flash('加载报告时发生错误', 'danger')
        return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
