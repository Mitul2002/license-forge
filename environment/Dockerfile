# License Forge challenge service.
# Build context is the task root (license-forge/), not this
# directory -- run from there: docker build -f environment/Dockerfile .
FROM python:3.12-slim

WORKDIR /app

COPY environment/build_keys.py /app/build_keys.py
COPY environment/server.py /app/server.py

# Key/flag generation happens once, at build time, so every container
# started from the same image is byte-identical (required for the
# environment-reliability calibration run).
RUN python3 /app/build_keys.py

EXPOSE 5000

CMD ["python3", "/app/server.py"]
