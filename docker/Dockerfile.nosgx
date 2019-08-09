FROM ubuntu:18.04

COPY getting_started/setup_vm/ /setup_vm/
RUN apt update
RUN apt install -y ansible software-properties-common
RUN cd setup_vm; ansible-playbook -i local_nosgx *.yml
