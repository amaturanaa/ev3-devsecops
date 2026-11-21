pipeline {
    agent any

    environment {
        APP_IMAGE     = 'ev3-app'
        APP_CONTAINER = 'ev3-app'
    }

    stages {

        stage('1. Build') {
            steps {
                echo '==> Creando entorno virtual e instalando dependencias'
                sh '''
                    python3 -m venv venv
                    . venv/bin/activate
                    pip install --upgrade pip
                    pip install -r requirements.txt
                '''
            }
        }

        stage('2. Gestion de dependencias') {
            steps {
                echo '==> Buscando vulnerabilidades conocidas en las dependencias (pip-audit)'
                sh '''
                    . venv/bin/activate
                    pip install pip-audit
                    pip-audit -r requirements.txt --desc -f markdown -o reporte-dependencias.md || true
                    pip-audit -r requirements.txt --desc
                '''
            }
        }

        stage('3. Test') {
            steps {
                echo '==> Ejecutando pruebas automatizadas de seguridad'
                sh '''
                    . venv/bin/activate
                    pip install pytest
                    pytest -v --junitxml=resultados-tests.xml test_app.py
                '''
            }
            post {
                always {
                    junit 'resultados-tests.xml'
                }
            }
        }

        stage('4. Deploy') {
            steps {
                echo '==> Desplegando la aplicacion en un contenedor Docker'
                sh '''
                    docker build -t $APP_IMAGE .
                    docker rm -f $APP_CONTAINER || true
                    docker run -d --name $APP_CONTAINER -p 5000:5000 $APP_IMAGE
                    sleep 5
                    docker ps --filter name=$APP_CONTAINER
                    docker exec $APP_CONTAINER python -c "import urllib.request; print('Estado de la app:', urllib.request.urlopen('http://127.0.0.1:5000/login').status)"
                '''
            }
        }
        
        stage('5. ZAP') {
            environment {
                ZAP_API_KEY = credentials('zap-api-key')
                ZAP_URL     = 'http://zap:8090'
                TARGET_URL  = 'http://host.docker.internal:5000'
                EXTRA_PATHS = '/ /login /dashboard'     
            }
            options { timeout(time: 25, unit: 'MINUTES') }
            steps {
                script {
                    def rc = sh(returnStatus: true, script: '''#!/bin/bash
set -euo pipefail
Z() { code=$(curl -s -G -o /tmp/zap.out -w '%{http_code}' "$ZAP_URL$1" "${@:2}" --data-urlencode "apikey=$ZAP_API_KEY") || return 1
  if [ "$code" -ge 400 ]; then echo "ERROR ZAP $1 -> HTTP $code: $(cat /tmp/zap.out)" >&2; return 1; fi
  cat /tmp/zap.out; }
jget() { python3 -c "import sys,json;d=json.load(sys.stdin);print(d$1)"; }

# 1) Esperar a ZAP
for i in $(seq 1 30); do Z /JSON/core/view/version/ >/dev/null 2>&1 && break || sleep 2; done
Z /JSON/core/view/version/ >/dev/null

# 2) Sesión limpia + sembrar rutas
Z /JSON/core/action/newSession/ --data-urlencode "name=build${BUILD_NUMBER}" --data-urlencode "overwrite=true" >/dev/null
for p in $EXTRA_PATHS; do
  Z /JSON/core/action/accessUrl/ --data-urlencode "url=${TARGET_URL}${p}" --data-urlencode "followRedirects=true" >/dev/null
done

# 3) Spider
sid=$(Z /JSON/spider/action/scan/ --data-urlencode "url=$TARGET_URL" --data-urlencode "recurse=true" | jget "['scan']")
while :; do st=$(Z /JSON/spider/view/status/ --data-urlencode "scanId=$sid" | jget "['status']"); echo "Spider: $st%"; [ "$st" -ge 100 ] && break; sleep 3; done

# 4) Active scan
aid=$(Z /JSON/ascan/action/scan/ --data-urlencode "url=$TARGET_URL" --data-urlencode "recurse=true" | jget "['scan']")
while :; do st=$(Z /JSON/ascan/view/status/ --data-urlencode "scanId=$aid" | jget "['status']"); echo "Active scan: $st%"; [ "$st" -ge 100 ] && break; sleep 10; done

# 5) Reportes
mkdir -p zap-reports
Z /OTHER/core/other/htmlreport/ > zap-reports/zap-report.html
Z /OTHER/core/other/jsonreport/ > zap-reports/zap-report.json

# 6) Resumen por riesgo
Z /JSON/alert/view/alerts/ --data-urlencode "baseurl=$TARGET_URL" --data-urlencode "start=0" --data-urlencode "count=5000" > zap-reports/alerts.json
python3 - <<'PY'
import json, collections
a = json.load(open("zap-reports/alerts.json")).get("alerts", [])
c = collections.Counter(x["risk"] for x in a)
for k in ("High","Medium","Low","Informational"): print(f"{k}: {c.get(k,0)}")
open("zap-reports/resumen.txt","w").write(f"high={c.get('High',0)}\\n")
raise SystemExit(10 if c.get("High",0) else 0)
PY
''')
                    if (rc == 10)     { unstable('ZAP encontró vulnerabilidades de riesgo High (ver ZAP Report)') }
                    else if (rc != 0) { error("El stage ZAP falló (código ${rc})") }
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'zap-reports/**', allowEmptyArchive: true
                    publishHTML(target: [reportDir: 'zap-reports', reportFiles: 'zap-report.html',
                                         reportName: 'ZAP Report', keepAll: true, allowMissing: true])
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'reporte-dependencias.md, resultados-tests.xml', allowEmptyArchive: true
        }
        success {
            echo 'Pipeline completado: aplicacion desplegada en http://localhost:5000'
        }
        failure {
            echo 'El pipeline fallo: revisar la etapa marcada en rojo.'
        }
    }
}
