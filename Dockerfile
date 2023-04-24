FROM ubuntu:latest
LABEL authors="bartek"

ENTRYPOINT ["top", "-b"]