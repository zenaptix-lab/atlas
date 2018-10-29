pipeline {
    agent any

    parameters {
        booleanParam(name: 'RELEASE_BUILD', defaultValue: false, description: 'Is this a release build?')
    }

    environment {
        GIT_EMAIL = 'toolusr@zenaptix.com'
        GIT_USER = 'Tool User'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
                script {
                    // Fail fast if incorrect branch
                    if(!isValidBranch(env.BRANCH_NAME)){
                        error("Invalid branch. Only feature/master/PR/bug/hotfix branches are allowed.")
                    }
                }
            }
        }
        stage('Capture Build Information') {
            steps {
                script {

                    // Get git commit hash
                    env.GIT_HASH = sh(script: "git log -n 1 --pretty=format:'%H' | cut -c 1-7", returnStdout: true)

                    // Get jenkins build information
                    env.BUILD_VERSION = VersionNumber(versionNumberString: '${BUILD_YEAR}-${BUILD_MONTH, XX}-${BUILD_NUMBER}')

                    env.SRC_VERSION = sh( script: '''
                            cat pom.xml | grep "^    <version>.*</version>$" | awk -F'[><]' '{print $3}'
                       ''', returnStdout: true).trim()

                    if(!isValidVersion(env.SRC_VERSION,env.BRANCH_NAME)){
                        error("Incorrect version is being used")
                    }

                    if( isFeatureBranch(env.BRANCH_NAME) || isBugBranch(env.BRANCH_NAME) ){

                        // extract jira tag
                        def tag = $/echo ${env.BRANCH_NAME} | sed -r 's/(feature|bug)\/([A-Z]{1,4}-[0-9]+)-.*|.*/\2/'/$
                        env.JIRA_TAG = sh(returnStdout:true, script:tag).trim()

                        // Fail if jira tag could not be extracted
                        if(env.JIRA_TAG == ""){
                            error("Could not extract Jira tag from branch name")
                        }

                        print "Jira Tag: ${env.JIRA_TAG}"

                        //replace version.sbt in feature build
                        sh """mvn versions:set -DnewVersion=${getFeatureOrBugJarTag("${env.SRC_VERSION}","${env.JIRA_TAG}")}"""

                        // Update SRC_VERSION because of change
                        env.SRC_VERSION = sh( script: '''
                            cat pom.xml | grep "^    <version>.*</version>$" | awk -F'[><]' '{print $3}'
                       ''', returnStdout: true).trim()

                    } else if (isValidBranch(env.BRANCH_NAME)) {
                        // No operation
                    } else {
                        error("Invalid branch. Only feature/master/PR/bug/hotfix branches are allowed.")
                    }

                    print "Branch Name: ${env.BRANCH_NAME}"
                    print "Git Commit Hash: ${env.GIT_HASH}"
                    print "Build Information: ${env.BUILD_VERSION}"
                    print "SRC Version: ${env.SRC_VERSION}"

                }
            }
        }
        stage('Confirm Release') {
            when {
                expression {
                    return params.RELEASE_BUILD
                }
            }
            steps {
                script{
                    if(isMasterBranch(env.BRANCH_NAME) || isHotfixBranch(env.BRANCH_NAME)){
                        print("This is a valid branch for release")
                    }else{
                        error("Only master or hotfix branches can be released.")
                    }
                }
                timeout(time: 1, unit: 'MINUTES') {
                    input "Should I release version ${srcVersionWithoutSnapshot(env.SRC_VERSION)}?"
                }
                script {
                    if(isMasterBranch(env.BRANCH_NAME)){
                        env.RELEASE_SCOPE = input message: 'Next version?', ok: 'Release!',
                                parameters: [choice(name: 'RELEASE_SCOPE', choices: 'Patch\nMinor\nMajor', description: 'How should I bump the version?')]
                    }else{
                        env.RELEASE_SCOPE = "Nano"
                    }

                }
            }

        }

        stage('Build Artifacts') {
            steps {
                script{
                    sh """mvn clean -DskipTests -Drat.skip=true -U -X install"""
                    sh """mvn clean -DskipTests -Drat.skip=true package -Pdist"""
                }
            }
        }
        stage('Publish Artifacts'){
            when {
                expression {
                    return !params.RELEASE_BUILD && !isPRBranch(env.BRANCH_NAME)
                }
            }
            steps {
                print "Publishing Artifacts"
                script{
                    sh 'mvn clean deploy -DskipTests -Drat.skip=true -e'
                }
            }
        }
        stage('Release and Publish Artifacts') {
            when {
                expression {
                    return params.RELEASE_BUILD && !isPRBranch(env.BRANCH_NAME)
                }
            }
            steps {
                print "Setting up git config"
                sh "git config user.email \'${env.GIT_EMAIL}\'"
                sh "git config user.name \'${env.GIT_USER}\'"
                sh "git config remote.origin.fetch +refs/heads/*:refs/remotes/origin/*"
                sh "git config branch.${env.BRANCH_NAME}.remote origin"
                sh "git config branch.${env.BRANCH_NAME}.merge refs/heads/${env.BRANCH_NAME}"
                print "Starting mvn release"
                mvnCustomRelease(env.RELEASE_SCOPE)
            }
        }
    }
    post {
        always {
            print 'Cleaning up Workspace'
            deleteDir()
        }
    }
}


// Return Feature SNAPSHOT JAR Tag
// <Major>.<Minor>.<Patch>-<Jira Issue Tag>-SNAPSHOT
// eg: 2.1.3-DF-329-SNAPSHOT

def getFeatureOrBugJarTag(srcVersion, jiraTag) {
    tag = "${srcVersionWithoutSnapshot(srcVersion)}-${jiraTag}-SNAPSHOT"
    return tag
}

// Remove snapshot from src version
def srcVersionWithoutSnapshot(srcVersion) {
    def removeSnap = $/echo ${srcVersion} | cut -d '-' -f1/$
    return sh(returnStdout:true, script:removeSnap).trim()
}

// Check if provided branch is a feature branch
def isFeatureBranch(branchName){
    isValid = false

    if(branchName.matches('(feature)\\/([A-Z]{1,4}-[0-9]+)-.*')){
        isValid = true
    }
    return isValid
}

// Check if provided branch is a bug branch
def isBugBranch(branchName){
    isValid = false

    if(branchName.matches('(bug)\\/([A-Z]{1,4}-[0-9]+)-.*')){
        isValid = true
    }
    return isValid
}

// Check if provided branch is the hotfix branch
def isHotfixBranch(branchName){
    isValid = false

    if(branchName.matches('(hotfix)\\/([A-Z]{1,4}-[0-9]+)-.*')){
        isValid = true
    }
    return isValid
}

// Check if provided branch is the master branch
def isMasterBranch(branchName){
    isValid = false

    if(branchName.matches('(master$)')){
        isValid = true
    }
    return isValid
}

// Check if provided branch is a pull request branch
def isPRBranch(branchName){
    isValid = false

    if(branchName.matches('^PR-[0-9]+(-merge|-head)?$')){
        isValid = true
    }
    return isValid
}

// Check if provided branch is valid
def isValidBranch(branchName){
    return isBugBranch(branchName) ||
            isPRBranch(branchName) ||
            isMasterBranch(branchName) ||
            isFeatureBranch(branchName) ||
            isHotfixBranch(branchName)
}

// Find version that will be published
// If release remove snapshot, else use srcVersion
def getVersionToPublish(srcVersion, isRelease){
    versionToPublish = srcVersion

    if(isRelease){
        versionToPublish = srcVersionWithoutSnapshot(srcVersion)
    }

    return versionToPublish
}

// Check if version supplied in repo is valid for a branch
def isValidVersion(srcVersion,branchName){

    isValid = false

    if(env.SRC_VERSION.matches('([0-9]+.[0-9]+.[0-9]+-SNAPSHOT$)') &&
            (isFeatureBranch(branchName)|| isBugBranch(branchName) || isMasterBranch(branchName) || isPRBranch(branchName))){
        isValid = true
    }else if(env.SRC_VERSION.matches('([0-9]+.[0-9]+.[0-9]+.[0-9]+-SNAPSHOT$)') && isHotfixBranch(branchName)){
        isValid = true
    }

    return isValid
}

// Maven release with version bump
def mvnCustomRelease(releaseScope){

  if(releaseScope == "Major"){
    sh 'mvn build-helper:parse-version release:prepare -B -Darguments=\\"-Dmaven.test.skip=true\\" -DdevelopmentVersion=\\${parsedVersion.nextMajorVersion}.0.0-SNAPSHOT'
  }else if(releaseScope == "Minor"){
    sh 'mvn build-helper:parse-version release:prepare -B -Darguments=\\"-Dmaven.test.skip=true\\" -DdevelopmentVersion=\\${parsedVersion.majorVersion}.\\${parsedVersion.nextMinorVersion}.0-SNAPSHOT'
  }else if(releaseScope == "Patch"){
    sh 'mvn build-helper:parse-version release:prepare -B -Darguments=\\"-Dmaven.test.skip=true\\" -DdevelopmentVersion=\\${parsedVersion.majorVersion}.\\${parsedVersion.minorVersion}.\\${parsedVersion.nextIncrementalVersion}-SNAPSHOT'
  }else if(releaseScope == "Nano"){
    sh 'mvn build-helper:parse-version release:prepare -B -Darguments=\\"-Dmaven.test.skip=true\\"'
  }

  sh 'mvn -B -Darguments=\\"-Dmaven.test.skip=true\\" release:perform'
  sh "git push origin --tags"
  sh "git push origin"
}