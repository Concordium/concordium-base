pipeline {
    agent any

    environment {
        image_repo = 'concordium/identity-provider-service'
        image_name = "${image_repo}:${image_tag}"
    }

    stages {
        stage('dockerhub-login') {
            environment {
                // Defines 'CRED_USR' and 'CRED_PSW'
                // (see 'https://www.jenkins.io/doc/book/pipeline/jenkinsfile/#handling-credentials').
                CRED = credentials('jenkins-dockerhub')
            }
            steps {
                sh 'echo "${CRED_PSW}" | docker login --username "${CRED_USR}" --password-stdin'
            }
        }
        stage('build') {
            steps {
                sh '''\
                    docker build \
                      -t "${image_name}" \
                      --build-arg development_image_tag="${development_image_tag}" \
                      --label development_image_tag="${development_image_tag}" \
                      -f scripts/identity-provider-service.Dockerfile \
                      .
                    docker push "${image_name}"
                '''
            }
        }
    }
}
