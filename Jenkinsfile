@Library('toucan-jenkins-lib')_
import com.toucantoco.ToucanVars

pipeline {
  agent any

  options {
    // Enable color in logs
    ansiColor('gnome-terminal')
  }

  environment {
    LICENSE_CONTENT = credentials('curity_testing_license')
    GH_TOKEN               = credentials('ngx_phantom_token_github_token')
    GH_VERSION             = '2.62.0'
    GH_SHA                 = '41c8b0698ad3003cb5c44bde672a1ffd5f818595abd80162fbf8cc999418446a'
  }

  stages {
    stage('Build') {
      steps {
        storeStage()
        sh './buildall.sh'
      }
    }

    stage('Test') {
      steps {
        storeStage()
        sh """
          cd testing/integration
          echo \"\$LICENSE_CONTENT\" > license.json
          LICENSE_FILE_PATH=license.json ./deploy.sh
        """
      }
    }

    stage('Deploy') {
      when {
        buildingTag()
      }
      steps {
        storeStage()
        sh 'PUSH=true ./buildall.sh'

        sh """
        if ! command -v gh > /dev/null; then
          mkdir -p tmp/bin/
          curl -fsSL "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_amd64.tar.gz" -o tmp/bin/gh.tar.gz
          echo "${GH_SHA} tmp/bin/gh.tar.gz" | sha256sum -c -
          tar xzf tmp/bin/gh.tar.gz --strip-components=2 -C tmp/bin/ gh_${GH_VERSION}_linux_amd64/bin/gh
          chmod +x tmp/bin/gh
        fi

        cd build/ && sha256sum -b * > checksums.txt && cd -
        cat << EOF > release_body.md
# Release ${env.BRANCH_NAME}

## SHA256 Checksums

```shell
\$(cat build/checksums.txt)
```
EOF

        tmp/bin/gh release create ${env.BRANCH_NAME} --title "${env.BRANCH_NAME}" --body-file release_body.md --generate-notes build/*
        """
      }
    }
  }

  post {
    failure {
      postSlackNotif()
    }

    cleanup {
      deleteDir()
    }

    always {
      // Store build result in a format parsable for our Elastic stack
      logKibana()
    }
  }
}
