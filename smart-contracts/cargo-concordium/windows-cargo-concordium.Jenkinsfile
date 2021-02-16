pipeline {
    agent { label 'windows' }
    stages {
        stage('build') {
            steps {
                
                sh '''\
                    # Extract version from Cargo.toml, if not set as parameter
                    [ -z "$VERSION" ] && VERSION=$(awk '/version = / { print substr($3, 2, length($3)-2); exit }' cargo-concordium/Cargo.toml)
                    OUTFILE=s3://static-libraries.concordium.com/dist-windows/cargo-concordium_${VERSION}.exe

                    # Fail if file already exists
                    totalFoundObjects=$(aws s3 ls ${OUTFILE} --summarize | grep "Total Objects: " | sed 's/[^0-9]*//g')
                    if [ "$totalFoundObjects" -ne "0" ]; then
                        echo "${OUTFILE} already exists"
                        false
                    fi   

                    # Set rust env
                    rustup default 1.45.2-x86_64-pc-windows-gnu

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
