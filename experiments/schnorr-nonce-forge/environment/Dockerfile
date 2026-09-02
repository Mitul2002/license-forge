# License Forge Identity Authority challenge service (Schnorr nonce reuse).
# Build context is the task root, not this directory --
# run from there: docker build -f environment/Dockerfile .
FROM python:3.12-slim

WORKDIR /app

COPY environment/build_keys.py /app/build_keys.py
COPY environment/server.py /app/server.py

# Domain-parameter/key/license generation happens once, at build time, so
# every container started from the same image is byte-identical.
RUN python3 /app/build_keys.py

EXPOSE 5000

CMD ["python3", "/app/server.py"]
