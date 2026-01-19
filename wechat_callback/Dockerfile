# 使用Python官方镜像作为基础镜像
FROM python:3.8-slim

# 设置工作目录
WORKDIR /callback_json_python3

# 安装系统依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    wget \
    xz-utils \
    xfonts-75dpi \
    xfonts-base \
    libxrender1 \
    libxext6 \
    fontconfig \
    libgl1 \
    libglib2.0-0 \
    ffmpeg \
    fonts-wqy-microhei \
    fonts-wqy-zenhei \
    wkhtmltopdf \
    && wget http://security.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2.24_amd64.deb \
    && dpkg -i --force-all libssl1.1_1.1.1f-1ubuntu2.24_amd64.deb || true \
    && rm libssl1.1_1.1.1f-1ubuntu2.24_amd64.deb \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*


# 复制后端代码
COPY . .

# 设置环境变量，使用已有的虚拟环境
ENV PATH="/callback_json_python3/env/bin:$PATH"
ENV VIRTUAL_ENV="/callback_json_python3/env"

# 暴露端口
EXPOSE 9530

# 启动应用，使用虚拟环境中的Python
CMD ["/callback_json_python3/env/bin/python", "wechat_callback.py"]