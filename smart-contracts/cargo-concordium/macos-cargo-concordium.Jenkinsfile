pipeline {
    agent none
    environment {
        BASE_OUTFILE = 's3://static-libraries.concordium.com/dist-macos/cargo-concordium'
    }
    stages {
        stage('precheck') {
            agent { label 'jenkins-worker' }
            steps {
                sh '''\
                    # Extract version number from package.yaml, if not set as parameter
                    [ -z "$VERSION" ] && VERSION=$(awk '/version = / { print substr($3, 2, length($3)-2); exit }' cargo-concordium/Cargo.toml)
                    OUTFILE="${BASE_OUTFILE}_${VERSION}"

                    # Fail if file already exists
                    totalFoundObjects=$(aws s3 ls ${OUTFILE} --summarize | grep "Total Objects: " | sed 's/[^0-9]*//g')
                    if [ "$totalFoundObjects" -ne "0" ]; then
                        echo "${OUTFILE} already exists"
                        false
                    fi
                '''.stripIndent()
            }
        }
        stage('build') {
            agent { label 'mac' }
            steps {
                
                sh '''\
                    # print rustc version, just for reference
                    rustup -V

                    cd cargo-concordium

                    # Build
                    cargo build --release 

                    # prepare output
                    mkdir out
                    cp ./target/release/cargo-concordium out/
                '''.stripIndent()
                stash includes: 'cargo-concordium/out/cargo-concordium', name: 'release'
            }
        }
        stage('Publish') {
            agent { label 'jenkins-worker' }
            steps {
                unstash 'release'
                sh '''\
                    # Push to s3
                    # Extract version number from package.yaml, if not set as parameter
                    [ -z "$VERSION" ] && VERSION=$(awk '/version = / { print substr($3, 2, length($3)-2); exit }' cargo-concordium/Cargo.toml)
                    OUTFILE="${BASE_OUTFILE}_${VERSION}"
                    aws s3 cp cargo-concordium/out/cargo-concordium ${OUTFILE} --grants read=uri=http://acs.amazonaws.com/groups/global/AllUsers
                '''.stripIndent()
            }
        }
    }
}