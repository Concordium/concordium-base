pipeline {
    agent none
    environment {
        FILENAME = 'libmobile_wallet.a'
        S3_BUCKET = 's3://static-libraries.concordium.com/iOS'
    }
    stages {
        stage('build') {
            agent { label 'mac' }
            steps {
                sh '''\
                    # Move into folder
                    cd mobile_wallet

                    # Prepare header
                    cbindgen src/lib.rs -l c > mobile_wallet.h

                    # Build
                    cargo lipo --release

                    # Prepate output
                    mkdir ../out
                    cp target/universal/release/${FILENAME} ../out/
                '''.stripIndent()
                stash includes: 'out/**/*', name: 'release'
            }
        }
        stage('Publish') {
            agent { label 'jenkins-worker' }
            options { skipDefaultCheckout() }
            steps {
                unstash 'release'
                sh '''\
                    # Push to s3
                    aws s3 cp "out/${FILENAME}" "${S3_BUCKET}/${FILENAME}" --grants read=uri=http://acs.amazonaws.com/groups/global/AllUsers
                '''.stripIndent()
            }
        }
    }
}
