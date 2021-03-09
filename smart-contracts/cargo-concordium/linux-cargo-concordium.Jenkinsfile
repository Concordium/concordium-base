pipeline {
    agent { label 'jenkins-worker' }
    environment {
        VERSION = sh(
            returnStdout: true, 
            script: '''\
                # Extract version number if not set as parameter
                [ -z "$VERSION" ] && VERSION=$(awk '/version = / { print substr($3, 2, length($3)-2); exit }' cargo-concordium/Cargo.toml)
                echo -n "$VERSION"
            '''.stripIndent()
        )
        OUTFILE = "s3://client-distribution.concordium.com/linux/cargo-concordium_${VERSION}"
    }
    stages {
        stage('ecr-login') {
            steps {
                sh 'aws ecr get-login-password \
                        --region eu-west-1 \
                    | docker login \
                        --username AWS \
                        --password-stdin 192549843005.dkr.ecr.eu-west-1.amazonaws.com'
            }
        }
        stage('precheck') {
            steps {
                sh '''\
                    # Fail if file already exists
                    totalFoundObjects=$(aws s3 ls "$OUTFILE" --summarize | grep "Total Objects: " | sed "s/[^0-9]*//g")
                    if [ "$totalFoundObjects" -ne "0" ]; then
                        echo "$OUTFILE already exists"
                        false
                    fi
                '''.stripIndent()
            }
        }
        stage('build') {
            agent { 
                docker {
                    image 'concordium/base:latest' 
                    registryUrl 'https://192549843005.dkr.ecr.eu-west-1.amazonaws.com/'
                    args '-u root'
                } 
            }
            steps {
                sh '''\
                    # Set rust env
                    rustup target add x86_64-unknown-linux-musl

                    cd cargo-concordium

                    # Build
                    cargo build --target x86_64-unknown-linux-musl --release


                    # Prepare output
                    mkdir ../out
                    cp target/x86_64-unknown-linux-musl/release/cargo-concordium ../out/
                '''.stripIndent()
                stash includes: 'out/cargo-concordium', name: 'release'
            }
            post {
                cleanup {
                    sh '''\
                        # Docker image has to run as root, otherwise user dosen't have access to node
                        # this means all generated files a owned by root, in workdir mounted from host
                        # meaning jenkins can't clean the files, so set owner of all files to jenkins
                        chown -R 1000:1000 .
                    '''.stripIndent()
                }
            }
        }
        stage('Publish') {
            steps {
                unstash 'release'
                sh '''\
                    # Push to s3
                    aws s3 cp "out/cargo-concordium" "${OUTFILE}"
                '''.stripIndent()
            }
        }
    }
}
