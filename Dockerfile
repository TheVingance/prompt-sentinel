FROM python:3.12-slim

# Evita criação de arquivos .pyc e força flush imediato nos logs
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Instala dependências de build necessárias para compilação C/C++
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copia requisitos e instala dependências Python
COPY requirements.txt /app/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copia o código da aplicação
COPY . /app/

# Expõe porta padrão da API
EXPOSE 8000

# Execução do Uvicorn com suporte assíncrono nativo
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
