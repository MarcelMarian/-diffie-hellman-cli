#!groovy

def artUploadServer = Artifactory.server('artifactory')
def snapshot = 'FOBCV'

pipeline {

    agent {
        label 'dind'
    }

    options {
        buildDiscarder(logRotator(artifactDaysToKeepStr: '1', artifactNumToKeepStr: '1', daysToKeepStr: '5', numToKeepStr: '10'))
    }

    environment { 
        ARCH = 'amd64' 
        NAME = 'diffie-hellman-service'
        VERSION = '1.0.0'
        DTR = 'registry.gear.ge.com'
        DTR_CREDS = credentials('CSP_DTR_CREDENTIALS')
        ARTIFACTORY_FOLDER = 'FOBCV/apps'
    }            

    stages {

        stage('Build and test') {
            steps {
                echo "Building"
                sh 'scripts/buildapplication'
                echo "Testing"
                sh 'scripts/testapplication'
            }
            post {
                success {
                    echo "OK"
                }
                failure {
                    echo "KO"
                }
            }
        }

        stage('Create and package container') {
            when {
                branch 'develop' // only deploy on certain branches
            }
            steps {
                echo "Building container"
                sh 'scripts/buildcontainer'
                sh 'docker login $DTR -u $DTR_CREDS_USR -p $DTR_CREDS_PSW'
                echo "Pushing container"
                sh 'scripts/pushcontainer'
                echo "Packaging container"
                sh 'scripts/packageapplication'
                script {
                  echo "Uploading to Artifactory"
                  def fileSpec = """{
                      "files": [
                        {
                          "pattern": "diffie-hellman-service-*.tar.gz",
                          "target": "${snapshot}/apps/"
                        }
                      ]
                  }"""
                  def buildInfo = artUploadServer.upload(fileSpec)
                  artUploadServer.publishBuildInfo(buildInfo)
                }
            }
            post {
                success {
                    echo "OK"
                }
                failure {
                    echo "KO"
                }
            }
        }

	}
}
