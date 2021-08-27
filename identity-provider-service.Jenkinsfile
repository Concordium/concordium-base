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
                sh 'docker login --username "${CRED_USR}" --password "${CRED_PSW}"'
            }
        }
        stage('build') {
            steps {
                sh '''\
                    docker build \
                      -t "${image_name}" \
                      --build-arg base_image_tag="${base_image_tag}" \
                      --label base_image_tag="${base_image_tag}" \
                      -f scripts/identity-provider-service.Dockerfile \
                      .
                    docker push "${image_name}"
                '''
            }
        }
    }
}
