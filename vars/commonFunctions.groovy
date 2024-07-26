def setGlobalVariables() {
    env.NFS_HOST=43.200.12.214
    env.NFS_DIR=data
    env.NFS_CREDENTIAL=jenkins-nfs-ssh
    env.GRADLE_CACHE_DIR=gradle
    env.TRIVY_CACHE_DIR=trivy-cache
    env.IMAGE_REG_PULL_SECRET=dockerhub
    env.IMAGE_PULL_POLICY=Always
    env.IMAGE_REG_CREDENTIAL=credential_cna_ondal
    env.BUILD_LIB_DIR=build/libs
    env.IMAGE_REG_HOST=docker.io
    env.IMAGE_REG_ORG=hiondal
    env.JAVA_BINARY_DIR=build/classes/java/main
    env.SONAR_SERVER_ID=SonarQube
}

def notifySlack(STATUS, COLOR) {
    //slackSend (channel: '#cicd', color: COLOR, message: STATUS+" : " +  "${env.JOB_NAME} [${env.BUILD_NUMBER}] (${env.BUILD_URL})")
}

def checkChangesInDirectory(String directory) {
    def changeLogSets = currentBuild.changeSets
    def hasChangesInDirectory = false

    for (int i = 0; i < changeLogSets.size(); i++) {
        def entries = changeLogSets[i].items
        for (int j = 0; j < entries.length; j++) {
            def entry = entries[j]
            def files = entry.affectedFiles
            //echo "*** Affected files count: " + files.size()
            for (int k = 0; k < files.size(); k++) {
                def file = files[k]
                //echo "*** Affected file: " + file.path
                if (file.path.startsWith("${directory}/")) {
                    hasChangesInDirectory = true
                    break
                }
            }
        }
    }

    return hasChangesInDirectory
}

def getTimestamp() {
    def dateFormat = new java.text.SimpleDateFormat("yyyyMMddHHmmss")
    def currentDate = new Date()
    def timestamp = dateFormat.format(currentDate)

    return timestamp
}

def getVulnerabilityResult(trivyOutput) {
    def vulnerabilityCounts = [:]
    def totalLine = trivyOutput.readLines().find { it.startsWith("Total:") }
    echo "Vulnerability: ${totalLine}"
    if (totalLine) {
        def countsPart = (totalLine =~ /\((.+)\)/)[0][1]
        countsPart.split(",").each { part ->
            def (severity, count) = part.trim().split(":")
            vulnerabilityCounts[severity] = count.trim().toInteger()
        }
    }
    
    /*
    echo "Vulnerability counts:"
    vulnerabilityCounts.each { severity, count ->
        echo "${severity}: ${count}"
    }
    */
    
    return vulnerabilityCounts
}

def getEurekaServiceUrl() {
    return "http://eureka:18080/eureka/"
}

def getConfigFQDN() {
    return "http://config:18080"
}



