FROM python:3.9-slim

# 安装系统依赖
RUN apt-get update && apt-get install -y \
    libevent-dev \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# 设置工作目录
WORKDIR /app

# 先安装基础依赖
COPY requirements.txt .
RUN pip install --no-cache-dir numpy==1.23.5 && \ 
    pip install --no-cache-dir -r requirements.txt

# 复制应用文件
COPY app ./app
COPY data ./data
COPY static ./static

# 设置环境变量
ENV PYTHONPATH=/app
ENV FLASK_APP=app/app.py
ENV FLASK_ENV=production

# 暴露端口
EXPOSE 5000

# 启动命令（使用gevent worker）
CMD ["gunicorn", \ 
    "--worker-class=gevent", \
    "--workers=4", \
    "--bind=0.0.0.0:5000", \
    "--timeout=120", \
    "app.app:app"]
