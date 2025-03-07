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
