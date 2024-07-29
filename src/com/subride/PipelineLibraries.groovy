
package com.subride

class PipelineLibraries implements Serializable {

    def script
    def envVars = [:]

    PipelineLibraries(script) {
        this.script = script
    }

    //-- 전역변수 셋팅: script.params로 시작하는 변수는 파이프라인 설정에서 값을 지정해야 함
    def setGlobalVariables() {
        script.stage('Set Global variables') {
            if (!validateParameters()) {
                script.error '파라미터가 정의되어 있지 않습니다. Pipeline 설정에서 파라미터를 정의하십시오.'
                return
            }

            envVars.SERVICE_GROUP = script.params.SERVICE_GROUP
            envVars.SERVICE_ID = script.params.SERVICE_ID
            envVars.SERVICE_VERSION = script.params.SERVICE_VERSION
            envVars.NFS_HOST = script.params.NFS_HOST
            envVars.IMAGE_REG_HOST = script.params.IMAGE_REG_HOST
            envVars.IMAGE_REG_CREDENTIAL = script.params.IMAGE_REG_CREDENTIAL
            envVars.IMAGE_REG_ORG = script.params.IMAGE_REG_ORG
            envVars.SKIP_STAGES = script.params.SKIP_STAGES
            envVars.EXPORT_PORT = script.params.EXPORT_PORT
            //envVars API_GATEWAY_FQDN = script.params.API_GATEWAY_FQDN
            envVars API_GATEWAY_FQDN = "scg.43.200.12.214.nip.io"

            envVars.NFS_DIR = 'data/nfs'                    //NFS 공유 디렉토리
            envVars.NFS_CREDENTIAL = 'jenkins-nfs-ssh'      //NFS 서버 접근 Credential(ssh username with private key 타입)

            envVars.GRADLE_CACHE_DIR = 'gradle'             //Gradle library 캐싱 디렉토리
            envVars.TRIVY_CACHE_DIR = 'trivy-cache'         //Trivy 캐싱 디렉토리
            envVars.NPM_CACHE_DIR = 'npm-cache'             //node modules 캐싱 디렉토리
            
            envVars.IMAGE_REG_PULL_SECRET = 'dockerhub'     //image pull secret
            envVars.IMAGE_PULL_POLICY = 'Always'            //Image Pull policy
            envVars.BUILD_LIB_DIR = 'build/libs'            //실행Jar 디렉토리
            envVars.JAVA_BINARY_DIR = 'build/classes/java/main' //class파일 디렉토리(SonqrQube에서 소스검사 때 사용)
            envVars.SONAR_SERVER_ID = 'SonarQube'           //Jenkins 시스템 설정에 이 이름으로  SonarQube서버 정보 설정해야 함

            envVars.SERVICE_GROUP_SC = 'sc'                 //Service Group 명 for Spring Cloud Services
            envVars.SERVICE_GROUP_SUBRIDE = 'subride'       //Service Group 명 for 구독관리 백엔드
            envVars.SERVICE_GROUP_SUBRIDE_FRONT = 'subride-front'   //Service Group 명 for 구독관리 프론트엔드

            envVars.PROJECT_DIR = getProjectDir()                //Service Group에 따른 Project 디렉토리를 셋팅
            if (envVars.SERVICE_GROUP == envVars.SERVICE_GROUP_SUBRIDE) {
                envVars.SUB_DIR_BIZ = envVars.PROJECT_DIR + '-biz'
                envVars.SUB_DIR_INFRA = envVars.PROJECT_DIR + '-infra'
            }
            envVars.PIPELINE_DIR = 'pipeline'               //pipeline 파일(Jenkinsfile, Dockerfile 등)디렉토리(프로젝트 Root 밑에 있어야 함)
            envVars.PIPELINE_ID = "${envVars.PROJECT_DIR}-${script.env.BUILD_NUMBER}"

            script.echo 'All global variables are set successfully!'
        }
    }

    //-- parameter 체크
    def validateParameters() {
        if (script.params.SERVICE_GROUP == '') { return false }
        if (script.params.SERVICE_ID == '') { return false }
        if (script.params.SERVICE_VERSION == '') { return false }
        if (script.params.NFS_HOST == '') { return false }
        if (script.params.IMAGE_REG_HOST == '') { return false }
        if (script.params.IMAGE_REG_CREDENTIAL == '') { return false }
        if (script.params.IMAGE_REG_ORG == '') { return false }
        if (envVars.SERVICE_GROUP == envVars.SERVICE_GROUP_SUBRIDE_FRONT) {
            if (script.params.EXPORT_PORT == '') { return false }
            //if (script.params.API_GATEWAY_FQDN == '') { return false }
        }

        return true
    }

    //-- Service ID별 Project 디렉토리를 리턴
    def getProjectDir() {
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

    //-- 소스 변경 여부 검사: 멀티 프로젝트이므로 타 서비스 소스 변경 시에도 파이프라인이 실행되어 검사 필요
    def checkSourceChanges() {
        script.stage('Check source changes') {
            if (envVars.SKIP_STAGES.contains('src')) {
                script.echo '[Check source changes] has been skipped!'
                return true    //source변경여부 체크 안함
            }

            if (envVars.SERVICE_GROUP == envVars.SERVICE_GROUP_SUBRIDE_FRONT) {
                script.echo envVars.SERVICE_GROUP_SUBRIDE_FRONT + "Don't need checking! Keep going!"
                return true   //프로트엔드는 검사 불필요
            }

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
                        if (file.path.startsWith("${envVars.PROJECT_DIR}/")) {
                            hasChangesInDirectory = true
                            break
                        }
                    }
                }
            }

            script.echo "${envVars.PROJECT_DIR} has changed source!"
            return hasChangesInDirectory
        }
    }

    //-- 실행환경 준비: 소스 변경 여부 검사, 캐싱 디렉토리 생성
    def createCacheDirectory() {
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
                script.stage('Prepare Cache Volumes') {
                    script.container('ssh') {
                        script.withCredentials([script.sshUserPrivateKey(credentialsId: "${envVars.NFS_CREDENTIAL}", keyFileVariable: 'SSH_KEY_FILE', usernameVariable: 'SSH_USER')]) {
                            script.sh """
                                mkdir -p ~/.ssh
                                ssh-keyscan -H ${envVars.NFS_HOST} >> ~/.ssh/known_hosts

                                if [ "${envVars.SERVICE_GROUP}" = "${envVars.SERVICE_GROUP_SC}" ] || [ "${envVars.SERVICE_GROUP}" = "${envVars.SERVICE_GROUP_SUBRIDE}" ]; then
                                    ssh -i \${SSH_KEY_FILE} \${SSH_USER}@${envVars.NFS_HOST} "sudo mkdir -p /${envVars.NFS_DIR}/${envVars.GRADLE_CACHE_DIR}/${envVars.SERVICE_ID}"
                                fi
                                
                                ssh -i \${SSH_KEY_FILE} \${SSH_USER}@${envVars.NFS_HOST} "sudo mkdir -p /${envVars.NFS_DIR}/${envVars.TRIVY_CACHE_DIR}/${envVars.SERVICE_ID}"
                            """
                        }
                    }
                }
            }
        }
    //----------------------------------------------
    }

    //*************************************** CI/CD 메인 처리 함수 **************************************
    def buildAndDeploy() {
        def containers = [
            script.containerTemplate(name: 'trivy', image: 'aquasec/trivy', ttyEnabled: true, command: 'cat'),
            script.containerTemplate(name: 'kubectl', image: 'lachlanevenson/k8s-kubectl', command: 'cat', ttyEnabled: true),
            script.containerTemplate(name: 'podman', image: 'mgoltzsche/podman', ttyEnabled: true, command: 'cat', privileged: true),
            script.containerTemplate(name: 'envsubst', image: 'hiondal/envsubst', command: 'sleep', args: '1h')
        ]
        if (envVars.SERVICE_GROUP in [envVars.SERVICE_GROUP_SC, envVars.SERVICE_GROUP_SUBRIDE]) {
            containers.add(script.containerTemplate(name: 'gradle', image: 'gradle:jdk17', ttyEnabled: true, command: 'cat'))
        } else {
            containers.add(script.containerTemplate(name: 'node', image: 'node:22.2.0-alpine3.20', ttyEnabled: true, command: 'cat'))
            containers.add(script.containerTemplate(name: 'sonar-scanner', image: 'sonarsource/sonar-scanner-cli', ttyEnabled: true, command: 'cat'))
        }

        def volumes = [
            script.nfsVolume(mountPath: "/${envVars.TRIVY_CACHE_DIR}", serverAddress: "${envVars.NFS_HOST}",
            serverPath: "/${envVars.NFS_DIR}/${envVars.TRIVY_CACHE_DIR}/${envVars.SERVICE_ID}", readOnly: false)
        ]

        if (envVars.SERVICE_GROUP in [envVars.SERVICE_GROUP_SC, envVars.SERVICE_GROUP_SUBRIDE]) {
            volumes.add(
                script.nfsVolume(mountPath: '/home/gradle/.gradle', serverAddress: "${envVars.NFS_HOST}",
                serverPath: "/${envVars.NFS_DIR}/${envVars.GRADLE_CACHE_DIR}/${envVars.SERVICE_ID}", readOnly: false)
            )
        }

        script.podTemplate(label: "${envVars.PIPELINE_ID}",
            containers: containers,
            volumes: volumes
        ) {
            script.node("${envVars.PIPELINE_ID}") {
                notifySlack('STARTED', '#FFFF00')

                //소스를 컨테이너 안으로 복사
                script.stage('Get Source') { script.checkout script.scm }

                //CI/CD 실행을 위한 변수 셋팅
                setCICDVariables()

                def skipStages = "${envVars.SKIP_STAGES}"  //건너 띌 스테이지 지정(sonar와 trivy skip가능)

                try {
                    if (envVars.SERVICE_GROUP in [envVars.SERVICE_GROUP_SC, envVars.SERVICE_GROUP_SUBRIDE]) {
                        //Build: 실행Jar파일 Build
                        script.stage('Build Jar') { buildJar() }
                    } else {
                        script.stage('Build Scripts') { buildScripts() }
                    }

                    if (!skipStages.contains('sonar')) {
                        //Build: 소스품질 검사
                        script.stage('SonarQube Analysis') {
                            if (envVars.SERVICE_GROUP in [envVars.SERVICE_GROUP_SC, envVars.SERVICE_GROUP_SUBRIDE]) {
                                sonarQubeAnalysisForJava()
                            } else {
                                sonarQubeAnalysisForScripts()
                            }
                        }

                        //Build: Quality Gate 충족 검사
                        script.stage('Verify Quality Gate') { verifyQualityGate() }
                    }

                    //Build: Build Container image
                    script.stage('Build Container Image') {
                        if (envVars.SERVICE_GROUP in [envVars.SERVICE_GROUP_SC, envVars.SERVICE_GROUP_SUBRIDE]) {
                            buildContainerImageForJava()
                        } else {
                            buildContainerImageForScripts()
                        }
                    }

                    //Build: image 보안 취약성 점검
                    if (!skipStages.contains('trivy')) {
                        script.stage('Scan Image Vulnerability') { scanContainerImageVulnerability() }
                    }

                    //Release:  Push Container image
                    script.stage('Push Container Image') { pushContainerImage() }

                    //Deploy: 배포 manifest 파일 생성
                    script.stage('Generate Manifest') { generateManifest() }

                    //Deploy: 배포
                    script.stage('Deploy') { deploy() }

                    //통보
                    script.currentBuild.result = 'SUCCESS'
                    notifySlack('SUCESS', '#00FF00')
                    script.echo '**** FINISH ALL STAGES : SUCCESS'
                } catch (e) {
                    script.currentBuild.result = 'FAILED'
                    notifySlack('FAILED', '#FF0000')
                    throw e
                }
            }
        }
    }
    //====================================================================

    //-- CI/CD 실행을 위한 변수 셋팅
    def setCICDVariables() {
        envVars.deployYamlDir = getdeployYamlDir()      //deployment yaml 파일이 있는 디렉토리 구함
        def props = script.readProperties file:"${envVars.deployYamlDir}/deploy_env_vars"

        envVars.applicationName = props['application_name'] //서비스명
        envVars.artifactoryFile = props['artifactory_file'] //서비스 실행 Jar명
        envVars.tag = getImageTag()                         //Container image tag 구하기
        envVars.namespace = props['namespace']              //배포할 네임스페이스
        envVars.manifest = props['manifest']                //배포 yaml 파일명
        envVars.imageScanSeverity = props['image_scan_severity']    //점검할 이미지 보안 취약성 등급(CRITICAL,HIGH,MEDIUM)
        envVars.sonarProjectKey = props['sonar_project_key']    //SonarQube에 생성한 project key(보통 service id와 동일)
        envVars.imagePath = "${envVars.IMAGE_REG_HOST}/${envVars.IMAGE_REG_ORG}/${envVars.applicationName}"

        envVars.eurekaServiceUrl = 'http://eureka:18080/eureka/'        //Eureka 서버 Url
        if (envVars.SERVICE_GROUP == envVars.SERVICE_GROUP_SUBRIDE) {
            envVars.configServerFQDN = 'http://config:18080'            //Config 서버 Url
        }
    }
    //-- image Tag를 동적으로 변경
    def getImageTag() {
        def dateFormat = new java.text.SimpleDateFormat('yyyyMMddHHmmss')
        def currentDate = new Date()
        def timestamp = dateFormat.format(currentDate)

        //return timestamp
        return envVars.SERVICE_VERSION      //현재는 버전을 리턴하나 실제 운영시에는 Timestamp를 리턴하게 변경 필요
    }

    //deployment yaml 파일이 있는 디렉토리 리턴
    def getdeployYamlDir() {
        if (envVars.SERVICE_GROUP == envVars.SERVICE_GROUP_SC || 
            envVars.SERVICE_GROUP == envVars.SERVICE_GROUP_SUBRIDE_FRONT  || 
            envVars.SERVICE_ID == 'transfer') {
            return "${envVars.PROJECT_DIR}/deployment"
        } else {
            return "${envVars.PROJECT_DIR}/${envVars.SUB_DIR_INFRA}/deployment"
        }
    }

    //-- Build: 실행Jar파일 Build
    def buildJar() {
        def buildDir = ''
        if (envVars.SERVICE_GROUP == envVars.SERVICE_GROUP_SC || envVars.SERVICE_ID == 'transfer') {
            buildDir = "${envVars.PROJECT_DIR}"
        } else {
            buildDir = "${envVars.PROJECT_DIR}:${envVars.SUB_DIR_INFRA}"
        }

        script.container('gradle') {
            script.sh 'echo "Build jar under build directory"'

            //실행 Jar 파일 빌드
            script.sh "gradle :${buildDir}:build -x test"
        }
    }

    //--Build: Scripts 파일 Build
    def buildScripts() {
        script.container('node') {
            script.sh """
                npm install --only=production
                npm run build --watch --watch-options-aggregate-timeout 1000
            """
        }
    }

    //-- Build: 소스품질 검사(Java)
    def sonarQubeAnalysisForJava() {
        def javaBinaries = ''
        if (envVars.SERVICE_GROUP == envVars.SERVICE_GROUP_SC || envVars.SERVICE_ID == 'transfer') {
            javaBinaries =  'build/classes/java/main'
        } else {
            javaBinaries = "${envVars.SUB_DIR_INFRA}/build/classes/java/main,${envVars.SUB_DIR_BIZ}/build/classes/java/main"
        }

        script.container('gradle') {
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

    //-- Build: 소스품질 검사(Scripts)
    def sonarQubeAnalysisForScripts() {
        script.container('sonar-scanner') {
            //--Jenkins System설정과 sonar-project.properties파일 내용을 기반으로 소스검사 수행
            script.withSonarQubeEnv("${envVars.SONAR_SERVER_ID}") {
                script.sh '''
                    sonar-scanner
                '''
            }
        }
    }

    //-- Build: Quality Gate 충족 검사
    //-- SonarQube의 Administrator에서 Web Hook 등록해야 함
    def verifyQualityGate() {
        script.timeout(time: 10, unit: 'MINUTES') {
            def qg = script.waitForQualityGate()
            if (qg.status != 'OK') {
                script.echo 'SonarQube Quality Gate failed. Aborting the pipeline.'
                script.currentBuild.result = 'FAILURE'
                notifySlack('SonarQube Quality Gate failed.', '#FF0000')
                script.error "Pipeline aborted due to SonarQube Quality Gate failure: ${qg.status}"
            }
        }
    }

    //-- Build: Build Container image(Java)
    def buildContainerImageForJava() {
        def buildBaseDir = getBuildBaseDir()
        script.container('podman') {
            script.sh """
                podman build -f ${envVars.PIPELINE_DIR}/Dockerfile \
                    -t ${envVars.imagePath}:${envVars.tag} \
                    --build-arg BUILD_LIB_DIR=${envVars.BUILD_LIB_DIR} \
                    --build-arg ARTIFACTORY_FILE=${envVars.artifactoryFile} \
                    ${buildBaseDir}
            """
        }
    }
    //-- Build: Build Container image(Scripts)
    def buildContainerImageForScripts() {
        def buildBaseDir = getBuildBaseDir()
        script.container('podman') {
            script.sh """
                podman build -f ${envVars.PIPELINE_DIR}/Dockerfile \
                    -t ${envVars.imagePath}:${envVars.tag} \
                    --build-arg PROJECT_FOLDER=${envVars.PROJECT_DIR} \
                    --build-arg BUILD_FOLDER=${envVars.PIPELINE_DIR} \
                    --build-arg EXPORT_PORT=${envVars.EXPORT_PORT} \
                    --build-arg REACT_APP_API_BASE_URL=${envVars.API_GATEWAY_FQDN} \
                    ${buildBaseDir}
            """
        }
    }

    //-- 이미지 빌드 시 기준 디렉토리 계산
    def getBuildBaseDir() {
        if (envVars.SERVICE_GROUP == envVars.SERVICE_GROUP_SC) {
            return "${envVars.PROJECT_DIR}"
        } else if (envVars.SERVICE_GROUP == envVars.SERVICE_GROUP_SUBRIDE && envVars.SERVICE_ID == 'transfer') {
            return "${envVars.PROJECT_DIR}"
        } else if (envVars.SERVICE_GROUP == envVars.SERVICE_GROUP_SUBRIDE) {
            return "${envVars.PROJECT_DIR}/${envVars.SUB_DIR_INFRA}"
        } else if (envVars.SERVICE_GROUP == envVars.SERVICE_GROUP_SUBRIDE_FRONT) {
            return '.'
        } else {
            return '.'
        }
    }

    //-- Build: image 보안 취약성 점검
    def scanContainerImageVulnerability() {
        script.timeout(time: 10, unit: 'MINUTES') {
            script.container('trivy') {
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

                script.echo 'Trivy scan results:'
                script.echo trivyOutput

                def vulnerabilityCounts = getVulnerabilityResult(trivyOutput)

                if (vulnerabilityCounts['CRITICAL'] > 0) {
                    script.echo 'Critical vulnerabilities found. Aborting the pipeline.'
                    script.currentBuild.result = 'FAILURE'
                    notifySlack('Vulnerability scan failed.', '#FF0000')
                    script.error 'Critical vulnerabilities found.'
                } else {
                    script.echo 'No critical vulnerabilities found. Continuing the pipeline.'
                }
            }
        }
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

    //-- Release:  Push Container image
    def pushContainerImage() {
        script.container('podman') {
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
        script.container('envsubst') {
            script.sh """
                set -a
                source ${envVars.deployYamlDir}/deploy_env_vars
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

                envsubst < ${envVars.deployYamlDir}/${envVars.manifest}.template > ${envVars.deployYamlDir}/${envVars.manifest}
                cat ${envVars.deployYamlDir}/${envVars.manifest}
            """
        }
    }

    //-- Deploy: 배포
    def deploy() {
        script.container('kubectl') {
            try {
                script.sh "kubectl delete deploy ${envVars.SERVICE_ID} -n ${envVars.namespace}"
            } catch (e) {
                script.echo "Error occurred while deleting the deployment: ${e}"
            }
            script.sh "kubectl apply -f ${envVars.deployYamlDir}/${envVars.manifest} -n ${envVars.namespace}"
        }
    }

    //-- Slack으로 통지
    def notifySlack(STATUS, COLOR) {
        // Implement Slack notification logic here
        // script.slackSend(channel: '#cicd', color: COLOR, message: STATUS + " : " + "${script.env.JOB_NAME} [${script.env.BUILD_NUMBER}] (${script.env.BUILD_URL})")
    }

}
