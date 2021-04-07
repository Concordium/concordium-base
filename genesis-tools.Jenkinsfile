// Params in JobDSL file
// 'https://gitlab.com/Concordium/infra/jenkins-jobs/-/blob/master/docker_image_genesis_tools.groovy':
// - image_tag (default: "latest")
// - base_image_tag

pipeline {
    agent any
    environment {
        image_repo = 'concordium/genesis-tools'
        image_name = "${image_repo}:${image_tag}"
    }
    stages {
	stage('dockerhub-login') {
            environment {
                CRED = credentials('jenkins-dockerhub')
            }
            steps {
                sh 'echo $CRED_PSW | docker login --username $CRED_USR --password-stdin'
            }
        }
        stage('build') {
            steps {
                sshagent(credentials: ['github-ci']) {
                    sh '''\
                        docker build \
                            --build-arg base_image_tag="$base_image_tag" \
                            --label base_image_tag="$base_image_tag" \
                            --label base_ref="$base_ref" \
                            --label git_commit="$GIT_COMMIT" \
                            -f "scripts/genesis-tools.Dockerfile" \
                            -t "$image_name" \
                            .
                    '''.stripIndent()
                }
            }
        }
        stage('push') {
            steps {
                sh 'docker push "$image_name"'
            }
        }
    }
}
