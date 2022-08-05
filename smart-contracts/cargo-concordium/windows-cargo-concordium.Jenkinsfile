pipeline {
    agent { label 'windows' }
    environment {
        BASE_OUTFILE = 's3://distribution.concordium.software/tools/windows/cargo-concordium'
    }
    stages {
        stage('build') {
            steps {
                
                sh '''\
                    # Extract version from Cargo.toml, if not set as parameter
                    [ -z "$VERSION" ] && VERSION=$(awk '/version = / { print substr($3, 2, length($3)-2); exit }' cargo-concordium/Cargo.toml)
                    OUTFILE=${BASE_OUTFILE}_${VERSION}.exe

                    # Fail if file already exists
                    totalFoundObjects=$(aws s3 ls ${OUTFILE} --summarize | grep "Total Objects: " | sed "s/[^0-9]*//g")
                    if [ "$totalFoundObjects" -ne "0" ]; then
                        echo "${OUTFILE} already exists"
                        false
                    fi   

                    # Set rust env
                    rustup default 1.62-x86_64-pc-windows-gnu

                    cd cargo-concordium

                    # Build
                    cargo build --release


                    # Push
                    aws s3 cp ./target/release/cargo-concordium.exe ${OUTFILE} --grants read=uri=http://acs.amazonaws.com/groups/global/AllUsers
                '''.stripIndent()
            }
        }
    }
}
