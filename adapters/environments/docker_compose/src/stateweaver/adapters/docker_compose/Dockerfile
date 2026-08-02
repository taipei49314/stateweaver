FROM python:3.13-alpine3.22@sha256:e81548ac35b07a3bd4805f275107592ef458b1e893c0e04d45aedaa19416cca5

WORKDIR /opt/stateweaver
COPY state_bridge.py /opt/stateweaver/state_bridge.py

RUN mkdir -p \
      /state/storage \
      /state/database \
      /state/cache \
      /state/queue \
      /state/session \
      /state/clock \
    && chown -R 65532:65532 /opt/stateweaver /state

USER 65532:65532
ENTRYPOINT ["python", "/opt/stateweaver/state_bridge.py"]
CMD ["serve"]
