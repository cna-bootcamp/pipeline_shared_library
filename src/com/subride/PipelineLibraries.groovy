
package com.subride

class PipelineLibraries implements Serializable {
    def script
    def envVars = [:]

    PipelineLibraries(script) {
        this.script = script
    }

    //--전역변수 셋팅: 서비스그룹, 서비스ID, 버전
    def setGlobalVariables(String serviceGroup, String serviceId, String version) {
        envVars.SERVICE_GROUP = serviceGroup
        envVars.SERVICE_ID = serviceId
        envVars.SERVICE_VERSION = version

        envVars.NFS_DIR = "data/nfs"
        envVars.NFS_CREDENTIAL = "jenkins-nfs-ssh"

        envVars.GRADLE_CACHE_DIR = "gradle"
        envVars.TRIVY_CACHE_DIR = "trivy-cache"
        envVars.IMAGE_REG_PULL_SECRET = "dockerhub"
        envVars.IMAGE_PULL_POLICY = "Always"
        envVars.BUILD_LIB_DIR = "build/libs"
        envVars.JAVA_BINARY_DIR = "build/classes/java/main"
        envVars.SONAR_SERVER_ID = "SonarQube"

        envVars.SERVICE_GROUP_SC = "sc"
        envVars.SERVICE_GROUP_SUBRIDE = "subride"
        envVars.SERVICE_GROUP_SUBRIDE_FRONT = "subride-front"

        envVars.SRC_DIR = getSourceDir()
        if (envVars.SERVICE_GROUP == envVars.SERVICE_GROUP_SUBRIDE) {
            envVars.SUB_DIR_BIZ = envVars.SRC_DIR + "-biz"
            envVars.SIB_DIR_INFRA = envVars.SRC_DIR + "-infra"
        }

        envVars.PIPELINE_ID = "${envVars.SRC_DIR}-${script.env.BUILD_NUMBER}"

        // 상황에 맞게 변경 필요
        envVars.NFS_HOST = "43.200.12.214"
        envVars.IMAGE_REG_CREDENTIAL = "credential_dockerhub_ondal"
        envVars.IMAGE_REG_HOST = "docker.io"
        envVars.IMAGE_REG_ORG = "hiondal"
    }

    def getSourceDir() {
        def sourceDirMap = [
            'config': 'config',
            'eureka': 'eureka',
            'scg': 'scg',
        ]
        
        return sourceDirMap.getOrDefault(envVars.SERVICE_ID, envVars.SERVICE_ID)
    }

    //-- 실행환경 준비
    def prepareEnvironment() {
        def hasChanges = true

        script.podTemplate(
            label: "${envVars.PIPELINE_ID}",
            containers: [
                script.containerTemplate(name: 'ssh', image: 'kroniak/ssh-client', command: 'cat', ttyEnabled: true),
            ]
        )
        {
            script.node("${envVars.PIPELINE_ID}") {
                script.stage("Prepare Cache Volumes") {
                    script.container("ssh") {
                        script.withCredentials([script.sshUserPrivateKey(credentialsId: "${envVars.NFS_CREDENTIAL}", keyFileVariable: 'SSH_KEY_FILE', usernameVariable: 'SSH_USER')]) {
                            script.sh """
                                mkdir -p ~/.ssh
                                ssh-keyscan -H ${envVars.NFS_HOST} >> ~/.ssh/known_hosts

                                if [ "${envVars.SERVICE_GROUP}" = "${envVars.SERVICE_GROUP_SC}" ] || [ "${envVars.SERVICE_GROUP}" = "${envVars.SERVICE_GROUP_SUBRIDE}" ]; then
                                    ssh -i \${SSH_KEY_FILE} \${SSH_USER}@${envVars.NFS_HOST} "sudo mkdir -p /${envVars.NFS_DIR}/${envVars.GRADLE_CACHE_DIR}/${envVars.SRC_DIR}"
                                fi
                                ssh -i \${SSH_KEY_FILE} \${SSH_USER}@${envVars.NFS_HOST} "sudo mkdir -p /${envVars.NFS_DIR}/${envVars.TRIVY_CACHE_DIR}/${envVars.SRC_DIR}"
                            """
                        }
                    }
                }

                script.stage("Check Source Changes") {
                    script.container('git') {
                        hasChanges = checkSourceChanges()
                        if (!hasChanges) {
                            script.currentBuild.result = 'SUCCESS'
                            
                        }
                    }
                }
            }            
        }

        return hasChanges
    }

    //---- 소스 변경 여부 검사
    def checkSourceChanges() {
        if (envVars.SERVICE_GROUP == envVars.SERVICE_GROUP_SUBRIDE_FRONT) return true

        def changeLogSets = script.currentBuild.changeSets
        def hasChangesInDirectory = false

        for (int i = 0; i < changeLogSets.size(); i++) {
            def entries = changeLogSets[i].items
            for (int j = 0; j < entries.length; j++) {
                def entry = entries[j]
                def files = entry.affectedFiles
                for (int k = 0; k < files.size(); k++) {
                    def file = files[k]
                    if (file.path.startsWith("${envVars.SRC_DIR}/")) {
                        hasChangesInDirectory = true
                        break
                    }
                }
            }
        }

        if (!hasChangesInDirectory) {
            return false
        }

        return true
    }

    //-- 실행을 위한 변수 셋팅
    def setCICDVariables() {
        envVars.baseDir = getBaseDir()
        def props = script.readProperties file:"${envVars.baseDir}/deploy_env_vars"
        envVars.applicationName = props["application_name"]
        envVars.artifactoryFile = props["artifactory_file"]
        envVars.tag = getImageTag()
        envVars.namespace = props["namespace"]
        envVars.manifest = props["manifest"]
        envVars.imageScanSeverity = props["image_scan_severity"]
        envVars.sonarProjectKey = props["sonar_project_key"]
        envVars.imagePath = "${envVars.IMAGE_REG_HOST}/${envVars.IMAGE_REG_ORG}/${envVars.applicationName}"

        envVars.eurekaServiceUrl = "http://eureka:18080/eureka/"
        if (envVars.SERVICE_GROUP == envVars.SERVICE_GROUP_SUBRIDE) {
            envVars.configServerFQDN = "http://config:18080"
        }
    }

    def getBaseDir() {
        if (envVars.SERVICE_GROUP == envVars.SERVICE_GROUP_SUBRIDE) {
            return "${envVars.SRC_DIR}/${envVars.SUB_DIR_INFRA}/deployment"
        } else {
            return "${envVars.SRC_DIR}/deployment"    
        }
    }
    //Build: build jar
    def buildJar() {
        def buildDir = getBuildDir()
        script.container("gradle") {
            script.sh 'echo "Build jar under build directory"'
            script.sh "gradle :${buildDir}:build -x test"
        }
    }

    //-- Build: 소스품질 검사
    def sonarQubeAnalysisForJava() {
        def javaBinaries = getJavaBinaries()
        script.container("gradle") {
            script.withSonarQubeEnv("${envVars.SONAR_SERVER_ID}") {
                script.sh """
                    gradle :${envVars.applicationName}:sonar \
                        -Dsonar.projectName=${envVars.sonarProjectKey} \
                        -Dsonar.projectKey=${envVars.sonarProjectKey} \
                        -Dsonar.java.binaries=${javaBinaries}
                """
            }
        }
    }
    def getJavaBinaries() {
        if (envVars.SERVICE_GROUP==envVars.SERVICE_GROUP_SUBRIDE) {
            return "${envVars.SUB_DIR_INFRA}/build/classes/java/main,${envVars.SUB_DIR_BIZ}/build/classes/java/main"
        } else {
            return "build/classes/java/main"
        }
    }

    //-- Build: Quality Gate 충족 검사
    def verifyQualityGate() {
        script.timeout(time: 10, unit: 'MINUTES') {
            def qg = script.waitForQualityGate()
            if (qg.status != 'OK') {
                script.echo "SonarQube Quality Gate failed. Aborting the pipeline."
                script.currentBuild.result = 'FAILURE'
                notifySlack("SonarQube Quality Gate failed.", "#FF0000")
                script.error "Pipeline aborted due to SonarQube Quality Gate failure: ${qg.status}"
            }
        }
    }

    //-- Build: Build Container image
    def buildContainerImageForJava() {
        def buildDir = getBuildDir()
        script.container("podman") {
            script.sh """
                podman build -f ./Dockerfile \
                    -t ${envVars.imagePath}:${envVars.tag} \
                    --build-arg BUILD_LIB_DIR=${envVars.BUILD_LIB_DIR} \
                    --build-arg ARTIFACTORY_FILE=${envVars.artifactoryFile} \
                        ${buildDir}
            """
        }
    }

    //-- Build: image 보안 취약성 점검
    def scanContainerImageVulnerability() {
        script.timeout(time: 10, unit: 'MINUTES') {
            script.container("trivy") {
                def trivyOutput = script.sh(
                    script: """
                        trivy image \
                            --cache-dir /${envVars.TRIVY_CACHE_DIR} \
                            --scanners vuln \
                            --severity ${envVars.imageScanSeverity} \
                            --exit-code 0 \
                            ${envVars.imagePath}:${envVars.tag}
                    """,
                    returnStdout: true
                ).trim()

                script.echo "Trivy scan results:"
                script.echo trivyOutput

                def vulnerabilityCounts = getVulnerabilityResult(trivyOutput)

                if (vulnerabilityCounts["CRITICAL"] > 0) {
                    script.echo "Critical vulnerabilities found. Aborting the pipeline."
                    script.currentBuild.result = 'FAILURE'
                    notifySlack("Vulnerability scan failed.", "#FF0000")
                    script.error "Critical vulnerabilities found."
                } else {
                    script.echo "No critical vulnerabilities found. Continuing the pipeline."
                }
            }
        }
    }

    //-- Release:  Push Container image
    def pushContainerImage() {
        script.container("podman") {
            script.withCredentials([script.usernamePassword(
                credentialsId: "${envVars.IMAGE_REG_CREDENTIAL}",
                usernameVariable: 'USERNAME',
                passwordVariable: 'PASSWORD'
            )]) {
                script.sh """
                    echo user "\${USERNAME}" password "\${PASSWORD}"
                    podman login ${envVars.IMAGE_REG_HOST} --username "\${USERNAME}" --password "\${PASSWORD}"
                    podman push ${envVars.imagePath}:${envVars.tag}

                    podman tag ${envVars.imagePath}:${envVars.tag} ${envVars.imagePath}:latest
                    podman push ${envVars.imagePath}:latest
                """
            }
        }
    }

    //-- Deploy: 배포 manifest 파일 생성
    def generateManifest() {
        script.container("envsubst") {
            script.sh """
                set -a
                source ${envVars.baseDir}/deploy_env_vars
                set +a

                export tag=${envVars.tag}
                export image_pull_secret=${envVars.IMAGE_REG_PULL_SECRET}
                export image_pull_policy=${envVars.IMAGE_PULL_POLICY}
                export image_path=${envVars.imagePath}:${envVars.tag}

                if [ "${envVars.SERVICE_GROUP}" = "${envVars.SERVICE_GROUP_SC}" ] || [ "${envVars.SERVICE_GROUP}" = "${envVars.SERVICE_GROUP_SUBRIDE}" ]; then
                    export eureka_service_url=${envVars.eurekaServiceUrl}
                fi
                if [ "${envVars.SERVICE_GROUP}" = "${envVars.SERVICE_GROUP_SUBRIDE}" ]; then
                    export config_server_fqdn=${envVars.configServerFQDN}
                fi

                envsubst < ${envVars.baseDir}/${envVars.manifest}.template > ${envVars.baseDir}/${envVars.manifest}
                cat ${envVars.baseDir}/${envVars.manifest}
            """
        }
    }

    //-- Deploy: 배포
    def deploy() {
        script.container("kubectl") {
            script.sh "kubectl apply -f ${envVars.baseDir}/${envVars.manifest} -n ${envVars.namespace}"
        }
    }

    //-- jar빌드와 이미지 빌드 시 기준 디렉토리 계산
    def getBuildDir() {
        if (envVars.SERVICE_GROUP == envVars.SERVICE_GROUP_SC) {    
            return "${envVars.SRC_DIR}"
        } else if (envVars.SERVICE_GROUP == envVars.SERVICE_GROUP_SUBRIDE) {    
            return "${envVars.SRC_DIR}/${envVars.SUB_DIR_INFRA}"
        } else if (envVars.SERVICE_GROUP == envVars.SERVICE_GROUP_SUBRIDE_FRONT) {    
            return "."
        } else {
            return "."
        }
    }

    //-- Slack으로 통지  
    def notifySlack(STATUS, COLOR) {
        // Implement Slack notification logic here
        // For example:
        // script.slackSend(channel: '#cicd', color: COLOR, message: STATUS + " : " + "${script.env.JOB_NAME} [${script.env.BUILD_NUMBER}] (${script.env.BUILD_URL})")
    }

    //-- image Tag를 동적으로 변경
    def getImageTag() {
        def dateFormat = new java.text.SimpleDateFormat("yyyyMMddHHmmss")
        def currentDate = new Date()
        def timestamp = dateFormat.format(currentDate)

        return envVars.SERVICE_VERSION
    }

    //-- image vulnerability 결과를 파싱하여 심각도 레벨별 count를 구함
    def getVulnerabilityResult(trivyOutput) {
        def vulnerabilityCounts = [:]
        def totalLine = trivyOutput.readLines().find { it.startsWith("Total:") }
        script.echo "Vulnerability: ${totalLine}"
        if (totalLine) {
            def countsPart = (totalLine =~ /\((.+)\)/)[0][1]
            countsPart.split(",").each { part ->
                def (severity, count) = part.trim().split(":")
                vulnerabilityCounts[severity] = count.trim().toInteger()
            }
        }
        
        return vulnerabilityCounts
    }

}