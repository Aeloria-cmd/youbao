# pivot 工具目录

构建镜像前先运行 `bash build-assets/fetch-pivot-tools.sh`，
本目录会放入 chisel（内网隧道）和 socat（端口转发）静态二进制，
Dockerfile 将其 COPY 到镜像内 /opt/pivot/。

若下载失败可手工放置（linux/amd64 静态二进制），或留空——Dockerfile 会跳过缺失文件。
