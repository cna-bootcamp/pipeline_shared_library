package com.subride

class CommonFunctions implements Serializable {
    def script
    def envVars = [:]

    CommonFunctions(script) {
        this.script = script
    }

    //-- 소스 변경 여부 검사: 멀티 프로젝트이므로 타 서비스 소스 변경 시에도 파이프라인이 실행되어 검사 필요
    def checkChangesInDirectory(String projectDir) {
        script.stage('Check source changes') {
            script.checkout script.scm

            def changeLogSets = script.currentBuild.changeSets
            def hasChangesInDirectory = false

            if (changeLogSets.size() == 0) {
                script.echo "It's the first running. Don't need checking! Keep going!"
                return true
            }

            for (int i = 0; i < changeLogSets.size(); i++) {
                def entries = changeLogSets[i].items
                for (int j = 0; j < entries.length; j++) {
                    def entry = entries[j]
                    def files = entry.affectedFiles
                    for (int k = 0; k < files.size(); k++) {
                        def file = files[k]
                        //script.echo "Changed source => "+file.path + " <-> ${envVars.PROJECT_DIR}"
                        if (file.path.startsWith("${projectDir}/")) {
                            hasChangesInDirectory = true
                            break
                        }
                    }
                }
            }

            script.echo "${projectDir} has changed source!"
            return hasChangesInDirectory
        }
    }

    //-- Slack으로 통지
    def notifySlack(STATUS, COLOR) {
        // Implement Slack notification logic here
        // script.slackSend(channel: '#cicd', color: COLOR, message: STATUS + " : " + "${script.env.JOB_NAME} [${script.env.BUILD_NUMBER}] (${script.env.BUILD_URL})")
    }

    //-- image Tag를 동적으로 변경
    def getImageTag() {
        def dateFormat = new java.text.SimpleDateFormat('yyyyMMddHHmmss')
        def currentDate = new Date()
        def timestamp = dateFormat.format(currentDate)

        return timestamp
    }
    
    //-- image vulnerability 결과를 파싱하여 심각도 레벨별 count를 구함
    def getVulnerabilityResult(trivyOutput) {
        def vulnerabilityCounts = [:]
        def totalLine = trivyOutput.readLines().find { it.startsWith('Total:') }
        script.echo "Vulnerability: ${totalLine}"
        if (totalLine) {
            def countsPart = (totalLine =~ /\((.+)\)/)[0][1]
            countsPart.split(',').each { part ->
                def (severity, count) = part.trim().split(':')
                vulnerabilityCounts[severity] = count.trim().toInteger()
            }
        }

        return vulnerabilityCounts
    }
}
