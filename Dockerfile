FROM python:3.12-slim

WORKDIR /app

# Instalar solo las dependencias declaradas y con version fija
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el codigo de la aplicacion e inicializar la base de datos
COPY app.py init_db.py ./
RUN python init_db.py

# Ejecutar la aplicacion con un usuario sin privilegios (no root)
RUN useradd --create-home appuser && chown -R appuser /app
USER appuser

EXPOSE 5000
CMD ["python", "app.py"]
