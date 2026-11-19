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
