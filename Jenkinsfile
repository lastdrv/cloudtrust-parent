pipeline {
  agent any
  options {
    timestamps()
    timeout(time: 3600, unit: 'SECONDS')
  }
  parameters {
    string(name: 'BROWSER', defaultValue: 'firefox')
    string(name: 'SKIP_TESTS', defaultValue: 'false')
  }
  stages {
    stage('Build') {
      agent {
        label 'jenkins-slave-maven-ct'
      }
      steps {
        script {
          sh """
            mvn -B clean install package \
              -Dbrowser="${params.BROWSER}" \
              -DskipTests="${params.SKIP_TESTS}" \
              sonar:sonar \
              deploy \
              -DaltDeploymentRepository=artifactory::default::https://artifactory-test.multi.west.ch.elca-cloud.net/artifactory/cloudtrust-mvn/
          """
        }
      }
    }
  }
}
