
package com.subride

class PipelineLibraries implements Serializable {
    def script
    def envVars = [:]

    PipelineLibraries(script) {
        this.script = script
    }

    //-- 전역변수 셋팅: script.params로 시작하는 변수는 파이프라인 설정에서 값을 지정해야 함 
    def setGlobalVariables() {
        envVars.SERVICE_GROUP = script.params.SERVICE_GROUP
        envVars.SERVICE_ID = script.params.SERVICE_ID
        envVars.SERVICE_VERSION = script.params.SERVICE_VERSION
        envVars.NFS_HOST = script.params.NFS_HOST
        envVars.IMAGE_REG_HOST = script.params.IMAGE_REG_HOST
        envVars.IMAGE_REG_CREDENTIAL = script.params.IMAGE_REG_CREDENTIAL
        envVars.IMAGE_REG_ORG = script.params.IMAGE_REG_ORG
        envVars.SKIPSTAGES = script.params.SKIPSTAGES

        envVars.NFS_DIR = "data/nfs"                    //NFS 공유 디렉토리
        envVars.NFS_CREDENTIAL = "jenkins-nfs-ssh"      //NFS 서버 접근 Credential(ssh username with private key 타입)

        envVars.GRADLE_CACHE_DIR = "gradle"             //Gradle library 캐싱 디렉토리
        envVars.TRIVY_CACHE_DIR = "trivy-cache"         //Trivy 캐싱 디렉토리
        envVars.IMAGE_REG_PULL_SECRET = "dockerhub"     //image pull secret
        envVars.IMAGE_PULL_POLICY = "Always"            //Image Pull policy
        envVars.BUILD_LIB_DIR = "build/libs"            //실행Jar 디렉토리
        envVars.JAVA_BINARY_DIR = "build/classes/java/main" //class파일 디렉토리(SonqrQube에서 소스검사 때 사용)
        envVars.SONAR_SERVER_ID = "SonarQube"           //Jenkins 시스템 설정에 이 이름으로  SonarQube서버 정보 설정해야 함

        envVars.SERVICE_GROUP_SC = "sc"                 //Service Group 명 for Spring Cloud Services
        envVars.SERVICE_GROUP_SUBRIDE = "subride"       //Service Group 명 for 구독관리 백엔드
        envVars.SERVICE_GROUP_SUBRIDE_FRONT = "subride-front"   //Service Group 명 for 구독관리 프론트엔드

        envVars.SRC_DIR = getSourceDir()                //Service Group에 따른 소스 디렉토리를 셋팅
        if (envVars.SERVICE_GROUP == envVars.SERVICE_GROUP_SUBRIDE) {
            envVars.SUB_DIR_BIZ = envVars.SRC_DIR + "-biz"
            envVars.SIB_DIR_INFRA = envVars.SRC_DIR + "-infra"
        }
        envVars.PIPELINE_DIR = "pipeline"               //pipeline 파일(Jenkinsfile, Dockerfile 등)디렉토리(프로젝트 Root 밑에 있어야 함)
        envVars.PIPELINE_ID = "${envVars.SRC_DIR}-${script.env.BUILD_NUMBER}"
    }

    //-- Service ID별 소스 디렉토리를 리턴  
    def getSourceDir() {
        def sourceDirMap = [
            'config': 'config',
            'eureka': 'eureka',
            'scg': 'scg',
            'member': 'member',
            'subrecommend': 'subrecommend',
            'mysub': 'mysub',
            'mygrp': 'mygrp',
            'transfer': 'transfer',
            'subride-front': '.'
        ]
        
        return sourceDirMap.getOrDefault(envVars.SERVICE_ID, envVars.SERVICE_ID)
    }

    //-- 실행환경 준비: 소스 변경 여부 검사, 캐싱 디렉토리 생성  
    def prepareEnvironment() {
        def hasChanges = true

        //---------- 소스변경 검사 
        script.stage("Check Source Changes") {
            hasChanges = checkSourceChanges()            
        }
        script.echo "********* Changes Source => ${hasChanges}"
        if (!hasChanges) return hasChanges
        //--------------------------------

        //-------- NFS서버의 공유 디렉토리 하위에 캐싱 디렉토리 생성  ---
        script.podTemplate(
            label: "${envVars.PIPELINE_ID}",
            containers: [
                script.containerTemplate(name: 'ssh', image: 'kroniak/ssh-client', command: 'cat', ttyEnabled: true),
            ]
        )
        {
            script.node("${envVars.PIPELINE_ID}") {
                //-- chching을 위해 NFS볼륨 마운트
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

            }            
        }
        //----------------------------------------------

        return hasChanges
    }

    //-- 소스 변경 여부 검사: 멀티 프로젝트이므로 타 서비스 소스 변경 시에도 파이프라인이 실행되어 검사 필요
    def checkSourceChanges() {
        if (envVars.SERVICE_GROUP == envVars.SERVICE_GROUP_SUBRIDE_FRONT) return true   //프로트엔드는 검사 불필요

        script.checkout script.scm 

        def changeLogSets = script.currentBuild.changeSets
        def hasChangesInDirectory = false

        for (int i = 0; i < changeLogSets.size(); i++) {
            def entries = changeLogSets[i].items
            for (int j = 0; j < entries.length; j++) {
                def entry = entries[j]
                def files = entry.affectedFiles
                for (int k = 0; k < files.size(); k++) {
                    def file = files[k]
                    //script.echo "Changed source => "+file.path + " <-> ${envVars.SRC_DIR}"
                    if (file.path.startsWith("${envVars.SRC_DIR}/")) {
                        hasChangesInDirectory = true
                        break
                    }
                }
            }
        }

        return hasChangesInDirectory
    }

    //=================== CI/CD 메인 처리 함수 ============================
    def buildAndDeploy() {
        def volumes = [
            script.nfsVolume(mountPath: "/${envVars.TRIVY_CACHE_DIR}", serverAddress: "${envVars.NFS_HOST}",
            serverPath: "/${envVars.NFS_DIR}/${envVars.TRIVY_CACHE_DIR}/${envVars.SRC_DIR}", readOnly: false)
        ]

        if (envVars.SERVICE_GROUP in [envVars.SERVICE_GROUP_SC, envVars.SERVICE_GROUP_SUBRIDE]) {
            volumes.add(
                script.nfsVolume(mountPath: "/home/gradle/.gradle", serverAddress: "${envVars.NFS_HOST}",
                serverPath: "/${envVars.NFS_DIR}/${envVars.GRADLE_CACHE_DIR}/${envVars.SRC_DIR}", readOnly: false)
            )
        }

        script.podTemplate(label: "${envVars.PIPELINE_ID}",
            containers: [
                script.containerTemplate(name: "trivy", image: "aquasec/trivy", ttyEnabled: true, command: "cat"),
                script.containerTemplate(name: "kubectl", image: "lachlanevenson/k8s-kubectl", command: "cat", ttyEnabled: true),
                script.containerTemplate(name: "gradle", image: "gradle:jdk17", ttyEnabled: true, command: "cat"),
                script.containerTemplate(name: 'podman', image: "mgoltzsche/podman", ttyEnabled: true, command: 'cat', privileged: true),
                script.containerTemplate(name: 'envsubst', image: "hiondal/envsubst", command: 'sleep', args: '1h')
            ],
            volumes: volumes
        ) {
            script.node("${envVars.PIPELINE_ID}") {
                notifySlack("STARTED", "#FFFF00")

                //script.stage("Get Source") { script.checkout script.scm }

                //CI/CD 실행을 위한 변수 셋팅
                setCICDVariables()

                def skipStages = "${envVars.SKIP_STAGES}"

                try {
                    script.stage("Build Jar") { buildJar() }

                    if(!skipStages.contains("sonar")) {
                        script.stage("SonarQube Analysis") { sonarQubeAnalysisForJava() }
                        script.stage("Verify Quality Gate") { verifyQualityGate() }
                    }
            
                    script.stage("Build Container Image") { buildContainerImageForJava() }

                    if(!skipStages.contains("trivy")) {                                 
                        script.stage("Scan Image Vulnerability") { scanContainerImageVulnerability() }
                    }                                   

                    script.stage("Push Container Image") { pushContainerImage() }

                    script.stage("Generate Manifest") { generateManifest() }
            
                    //script.stage("Deploy") { deploy() }

                    script.currentBuild.result = "SUCCESS"
                    notifySlack("SUCESS", "#00FF00") 
                    script.echo "**** FINISH ALL STAGES : SUCCESS"
                } catch(e) {
                    script.currentBuild.result = "FAILED"
                    notifySlack("FAILED", "#FF0000")
                    throw e
                }
            }
        }
    }
    //====================================================================

    //-- CI/CD 실행을 위한 변수 셋팅
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
                podman build -f ${envVars.PIPELINE_DIR}/Dockerfile \
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