# Stage 1: Python on Alpine plus the one dependency, then remove what the
# script never uses (pip itself, the IDE, docs data, C headers).
FROM python:3.13-alpine AS build
RUN pip install --no-cache-dir --no-compile --root-user-action=ignore cryptography \
 && pip uninstall -y --root-user-action=ignore pip \
 && rm -rf /usr/local/include \
           /usr/local/lib/python3.13/ensurepip \
           /usr/local/lib/python3.13/idlelib \
           /usr/local/lib/python3.13/pydoc_data \
           /usr/local/lib/python3.13/tkinter \
           /usr/local/lib/python3.13/turtledemo \
 && find /usr/local -depth -name __pycache__ -exec rm -rf {} +

# Stage 2: copy that file system into an empty image, so the files removed
# above are really gone (no hidden copies in lower layers).
FROM scratch
COPY --from=build / /
ENV PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    LANG=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY read_sni.py client_initial.txt ./
USER nobody
ENTRYPOINT ["python3", "/app/read_sni.py"]
