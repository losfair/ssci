FROM debian:bullseye

RUN apt-get update && apt-get install -y openssh-server net-tools htop curl && \
    useradd -p '*' -u 1000 user && mkdir -p /home/user/.ssh && chown -R user:user /home/user

COPY ./sshd_config /opt/sshd/sshd_config
COPY ./enclave-rpc /

CMD ["/enclave-rpc", "guest"]
