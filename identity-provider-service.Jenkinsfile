pipeline {
    agent any

    parameters {
        string(name: 'GENESIS_REF', defaultValue: 'master', description: 'Genesis ref - must be a branch or tag, not SHA!')
    }

    environment {
        DOCKER_BUILDKIT = 1
    }

    stages {
        stage('ecr-login') {
            steps {
                sh '$(aws --region eu-west-1 ecr get-login | sed -e \'s/-e none//g\')'
            }
        }
        stage('build') {
            steps {
                script {
                    if (params.GENESIS_REF == '') {
                        sh script: 'exit 1', label: 'missing ref for genesis-data'
                    }
                    VERSION_TAG = sh (
                        script: 'git rev-parse --verify HEAD',
                        returnStdout: true
                    ).trim()
                }
                sshagent(credentials: ['6a7625a8-34f4-4c39-b0be-ed5b49aabc16']) {
                    sh """\
                           docker build -t 192549843005.dkr.ecr.eu-west-1.amazonaws.com/concordium/identity-provider-service:$VERSION_TAG \
                             -f scripts/identity-provider-service.Dockerfile --ssh default --build-arg GENESIS_REF="${params.GENESIS_REF}" . --no-cache
                           docker push 192549843005.dkr.ecr.eu-west-1.amazonaws.com/concordium/identity-provider-service:$VERSION_TAG
                       """
                }
            }
        }
    }
}
