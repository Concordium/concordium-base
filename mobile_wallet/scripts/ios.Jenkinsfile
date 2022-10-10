pipeline {
    agent { label 'jenkins-worker' }
    environment {
        FILENAME_ROOT = 'libmobile_wallet'
        VERSION = sh(
            returnStdout: true,
            script: '''\
                # Extract version number if not set as parameter
                [ -z "$VERSION" ] && VERSION=$(awk '/version = / { print substr($3, 2, length($3)-2); exit }' mobile_wallet/Cargo.toml)
                echo -n "$VERSION"
            '''.stripIndent()
        )
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
                    ./scripts/build-ios.sh

                    # Prepate output
                    mkdir ../out
                    cp ./ios/build/${FILENAME_ROOT}.xcframework ../out/
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
                    aws s3 cp "out/${FILENAME_ROOT}.xcframework" "${S3_BUCKET}/${FILENAME_ROOT}_${VERSION}.xcframework" --grants read=uri=http://acs.amazonaws.com/groups/global/AllUsers
                '''.stripIndent()
            }
        }
    }
}
