//-- Pipeline 전역 변수 셋팅  
def setGlobalVariables(String serviceGroup, String serviceId, String version) {
    env.SERVICE_GROUP=serviceGroup
    env.SERVICE_ID = serviceId
    env.SERVICE_VERSION = version 

    env.NFS_DIR=data
    env.NFS_CREDENTIAL=jenkins-nfs-ssh

    env.GRADLE_CACHE_DIR=gradle
    env.TRIVY_CACHE_DIR=trivy-cache
    env.IMAGE_REG_PULL_SECRET=dockerhub
    env.IMAGE_PULL_POLICY=Always
    env.BUILD_LIB_DIR=build/libs
    env.JAVA_BINARY_DIR=build/classes/java/main
    env.SONAR_SERVER_ID=SonarQube   //이 이름으로 Jenkins 시스템 설정의 SonarQube servers에 등록되어 있어야 함

    env.SERVICE_GROUP_SC = "sc"
    env.SERVICE_GROUP_SUBRIDE = "subride"
    env.SERVICE_GROUP_SUBRIDE_FRONT = "subride-front"

    env.SRC_DIR = getSourceDir()
    if (env.SERVICE_GROUP == env.SERVICEGROUP_SUBRIDE) {
        env.SUB_DIR_BIZ = env.SRC_DIR+"-biz"
        env.SIB_DIR_INFRA = env.SRC_DIR+"-infra"
    }

    env.PIPELINE_ID = "${SRC_DIR}-${env.BUILD_NUMBER}"

    //-- 상황에 맞게 변경 필요  
    env.NFS_HOST=43.200.12.214
    env.IMAGE_REG_CREDENTIAL=credential_cna_ondal
    env.IMAGE_REG_HOST=docker.io
    env.IMAGE_REG_ORG=hiondal
}

//-- 서비스의 소스 디렉토리 리턴  
def getSourceDir() {
    def sourceDirMap = [
        'config': 'config',
        'eureka': 'eureka',
        'scg': 'scg',
        // 추가적인 serviceId와 소스 디렉토리 매핑을 여기에 추가
    ]
    
    return sourceDirMap.getOrDefault(env.SERVICE_ID, env.SERVICE_ID)
}

//-- 실행환경 준비  
def prepareEnvironment() {
    stage("Prepare Environment") {
        podTemplate(
            label: "${PIPELINE_ID}",
            containers: [
                containerTemplate(name: 'ssh', image: 'kroniak/ssh-client', command: 'cat', ttyEnabled: true),
            ]
        )
        {
            //-- NFS 공유 볼륨 디렉토리 생성
            node("${PIPELINE_ID}") {
                stage("Prepare Cache Volumes") {
                    container("ssh") {
                        withCredentials([sshUserPrivateKey(credentialsId: "${NFS_CREDENTIAL}", keyFileVariable: 'SSH_KEY_FILE', usernameVariable: 'SSH_USER')]) {
                            sh """
                                mkdir -p ~/.ssh
                                ssh-keyscan -H ${NFS_HOST} >> ~/.ssh/known_hosts

                                if (env.SERVICE_GROUP == env.SERVICEGROUP_SC || env.SERVICE_GROUP == env.SERVICEGROUP_SUBRIDE) {
                                    ssh -i ${SSH_KEY_FILE} ${SSH_USER}@${NFS_HOST} "sudo mkdir -p /${NFS_DIR}/${GRADLE_CACHE_DIR}/${SRC_DIR}"
                                }
                                ssh -i ${SSH_KEY_FILE} ${SSH_USER}@${NFS_HOST} "sudo mkdir -p /${NFS_DIR}/${TRIVY_CACHE_DIR}/${SRC_DIR}"
                            """
                        }
                    }
                }
            }
        }
    }
}

//-- Pod 구성  
def setPodTemplates() {
    def volumes = [
        nfsVolume(mountPath: "/${TRIVY_CACHE_DIR}", serverAddress: "${NFS_HOST}", serverPath: "/${NFS_DIR}/${TRIVY_CACHE_DIR}/${SRC_DIR}", readOnly: false)
    ]
    
    if (env.SERVICE_GROUP == env.SERVICEGROUP_SC || env.SERVICE_GROUP == env.SERVICEGROUP_SUBRIDE) {
        volumes.add(
            nfsVolume(mountPath: "/home/gradle/.gradle", serverAddress: "${NFS_HOST}", serverPath: "/${NFS_DIR}/${GRADLE_CACHE_DIR}/${SRC_DIR}", readOnly: false)
        )
    }
    
    podTemplate(
        label: "${PIPELINE_ID}",
        containers: [
            containerTemplate(name: "trivy", image: "aquasec/trivy", ttyEnabled: true, command: "cat"),
            containerTemplate(name: "kubectl", image: "lachlanevenson/k8s-kubectl", command: "cat", ttyEnabled: true),
            containerTemplate(name: "gradle", image: "gradle:jdk17", ttyEnabled: true, command: "cat"),
            containerTemplate(name: 'podman', image: "mgoltzsche/podman", ttyEnabled: true, command: 'cat', privileged: true),
            containerTemplate(name: 'envsubst', image: "hiondal/envsubst", command: 'sleep', args: '1h')
        ],
        volumes: volumes
    )    
}

//-- 현재 서비스 디렉토리 하위의 파일이 변경되었는지 검사  
def checkSourceChanges() {
    //--Font앱인 경우는 무조건 true 리턴
    if (env.SERVICE_GROUP == env.SERVICEGROUP_SUBRIDE_FRONT) return true

    //changeSets값을 이용하여 현재 서비스 디렉토리 내 파일이 변경되었는지 검사  
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
                if (file.path.startsWith("${SRC_DIR}/")) {
                    hasChangesInDirectory = true
                    break
                }
            }
        }
    }

    if (!hasChangesInDirectory) {
        echo "No changes in <${SRC_DIR}> directory. Skipping pipeline."
        currentBuild.result = 'STOP'
        //commonFunctions.notifySlack("SKIPPED", "#00FF00")
        return false
    }

    return true
}

def setCICDVariables() {
    env.baseDir = getBaseDir()
    def props = readProperties  file:"${baseDir}/deploy_env_vars"
    env.applicationName = props["application_name"]
    env.artifactoryFile = props["artifactory_file"]
    env.tag = getImageTag()
    env.namespace = props["namespace"]
    env.manifest = props["manifest"]
    env.imageScanSeverity = props["image_scan_severity"]
    env.sonarProjectKey = props["sonar_project_key"]
    env.imagePath = "${IMAGE_REG_HOST}/${IMAGE_REG_ORG}/${applicationName}"

    //-- 상황에 맞게 변경 필요 
    env.eurekaServiceUrl = "http://eureka:18080/eureka/"
    if (env.SERVICE_GROUP==env.SERVICEGROUP_SUBRIDE) {
        env.configServerFQDN = "http://config:18080"
    }
}

def getBaseDir() {
    if (env.SERVICE_GROUP==env.SERVICEGROUP_SUBRIDE) {
        return "${SRC_DIR}/${SUB_DIR_INFRA}/deployment"
    } else {
        return "${SRC_DIR}/deployment"    
    }
}

//-- Build jar
def stageBuildJar() {
    stage("Build Jar") {
        container("gradle") {
            sh 'echo "Build jar under build directory"'
            sh "gradle :${SRC_DIR}:${SUB_DIR_INFRA}:build -x test"
        }
    }    
}
//-- Build React scripts
def stageBuildScripts() {
    stage("Build React Scripts") {
        container("node") {
            sh """
                npm install

                npm run build --watch --watch-options-aggregate-timeout 1000
            """
        }
    }
}

//-- SonarQube를 이용한 소스 검사(Java) 
def stageSonarQubeAnalysisForJava() {
    def javaBinaries = getJavaBinaries()

    stage("SonarQube Analysis") {
        container("gradle") {
            withSonarQubeEnv("${SONAR_SERVER_ID}") {
                sh """
                    gradle :${applicationName}:sonar \
                        -Dsonar.projectName=${sonarProjectKey} \
                        -Dsonar.projectKey=${sonarProjectKey} \
                        -Dsonar.java.binaries=${javaBinaries}
                """
            }
        }    
}
def getJavaBinaries() {
    if (env.SERVICE_GROUP==env.SERVICEGROUP_SUBRIDE) {
        return "${SUB_DIR_INFRA}/build/classes/java/main,${SUB_DIR_BIZ}/build/classes/java/main"
    } else {
        return "build/classes/java/main"
    }
}

//-- SonarQube를 이용한 소스 검사(Scripts) 
def stageSonarQubeAnalysisForScripts {
    stage("SonarQube Analysis") {
        container("sonar-scanner") {
            //--Jenkins System설정과 sonar-project.properties파일 내용을 기반으로 소스검사 수행 
            withSonarQubeEnv("${SONAR_SERVER_ID}") {
                sh """
                    sonar-scanner
                """
            }
        }    
    }
}

//-- SonarQube Quality Gate 기준 충족여부 검사  
def stageVerifyQualityGate() {
    stage("Verify Quality Gate") {
        timeout(time: 10, unit: 'MINUTES') {
            def qg = waitForQualityGate()
            if (qg.status != 'OK') {
                echo "SonarQube Quality Gate failed. Aborting the pipeline."
                currentBuild.result = 'FAILURE'
                notifySlack("SonarQube Quality Gate failed.", "#FF0000")
                error "Pipeline aborted due to SonarQube Quality Gate failure: ${qg.status}"
            }
        }
    }    
}

//-- Build Container image for Java
def stageBuildContainerImageForJava() {
    def buildDir = getBuildDir()
    stage("Build Container image") {
        container("podman") {
            sh """
                podman build -f ./Dockerfile \
                    -t ${imagePath}:${tag} \
                    --build-arg BUILD_LIB_DIR=${BUILD_LIB_DIR} \
                    --build-arg ARTIFACTORY_FILE=${artifactoryFile} \
                        ${buildDir}
            """
        }
    }    
}
def getBuildDir() {
    if (env.SERVICE_GROUP==env.SERVICEGROUP_SC) {    
        return "${SRC_DIR}"
    } else if (env.SERVICE_GROUP==env.SERVICEGROUP_SUBRIDE) {    
        return "${SRC_DIR}/${SUB_DIR_INFRA}"
    } else if (env.SERVICE_GROUP==env.SERVICEGROUP_SUBRIDE_FRONT) {    
        return "."
    } else {
        return "."
    }
}

//-- Build Container image for Scripts
def stageBuildContainerImageForScripts() {
    stage("Build Container image") {
        container("podman") {
            withCredentials([usernamePassword(
                credentialsId: "${IMAGE_REG_CREDENTIAL}",
                usernameVariable: 'USER',
                passwordVariable: 'PASSWORD'
            )]) {
                sh """
                    echo user "$USER" pasword "$PASSWORD"
                    podman login ${IMAGE_REG_HOST} --username ${USER} --password ${PASSWORD}
                    podman build -f ${baseDir}/Dockerfile \
                        -t ${imagePath}:${tag} \
                        .
                    podman push ${imagePath}:${tag}

                    podman tag ${imagePath}:${tag} ${imagePath}:latest
                    podman push ${imagePath}:latest
                """
            }
        }
    }
}

//-- Container image의 보안 취약성 점검
def stageScanContainerImageVulnurability() {
    stage("Scan Image Vulnerability") {
        timeout(time: 10, unit: 'MINUTES') {
            container("trivy") {
                def trivyOutput = sh (
                    script: """
                        trivy image \
                            --cache-dir /${TRIVY_CACHE_DIR} \
                            --scanners vuln \
                            --severity ${imageScanSeverity} \
                            --exit-code 0 \
                            ${imagePath}:${tag}
                    """,
                    returnStdout: true
                ).trim()

                echo "Trivy scan results:"
                echo trivyOutput

                def vulnerabilityCounts = getVulnerabilityResult(trivyOutput)

                if (vulnerabilityCounts["CRITICAL"] > 0) {
                    echo "Critical vulnerabilities found. Aborting the pipeline."
                    currentBuild.result = 'FAILURE'
                    notifySlack("Vulnerability scan failed.", "#FF0000")
                    error "Critical vulnerabilities found."
                } else {
                    echo "No critical vulnerabilities found. Continuing the pipeline."
                }
            }
        }
    }
}

//-- Push container image
def stagePushContainerImage() {
    stage("Push Container image") {
        container("podman") {
            withCredentials([usernamePassword(
                credentialsId: "${IMAGE_REG_CREDENTIAL}",
                usernameVariable: 'USER',
                passwordVariable: 'PASSWORD'
            )]) {
                sh """
                    echo user "$USER" pasword "$PASSWORD"
                    podman login ${IMAGE_REG_HOST} --username ${USER} --password ${PASSWORD}
                    podman push ${imagePath}:${tag}

                    podman tag ${imagePath}:${tag} ${imagePath}:latest
                    podman push ${imagePath}:latest
                """
            }
        }
    }
}

//-- K8s Deploy manifest파일 생성  
def stageGenerateManifest() {
    stage( "Generate deployment yaml" ) {
        container("envsubst") {
            sh """
                set -a
                source ${baseDir}/deploy_env_vars
                set +a

                export tag=${tag}
                export image_pull_secret=${IMAGE_REG_PULL_SECRET}
                export image_pull_policy=${IMAGE_PULL_POLICY}
                export image_path=${imagePath}:${tag}

                if (env.SERVICE_GROUP == env.SERVICEGROUP_SC || env.SERVICE_GROUP == env.SERVICEGROUP_SUBRIDE) {
                    export eureka_service_url=${eurekaServiceUrl}
                }
                if (env.SERVICE_GROUP == env.SERVICEGROUP_SUBRIDE) {
                    export config_server_fqdn=${configServerFQDN}
                }

                envsubst < ${baseDir}/${manifest}.template > ${baseDir}/${manifest}
                cat ${baseDir}/${manifest}
            """
        }
    }    
}

//-- Deploy to k8s
def stageDeploy() {
    stage( "Deploy" ) {
        container("kubectl") {
            sh "kubectl apply -f ${baseDir}/${manifest} -n ${namespace}"
        }
    }    
}

//-- slack 통보 
def notifySlack(STATUS, COLOR) {
    //slackSend (channel: '#cicd', color: COLOR, message: STATUS+" : " +  "${env.JOB_NAME} [${env.BUILD_NUMBER}] (${env.BUILD_URL})")
}

def getImageTag() {
    def dateFormat = new java.text.SimpleDateFormat("yyyyMMddHHmmss")
    def currentDate = new Date()
    def timestamp = dateFormat.format(currentDate)

    //return timestamp
    return env.SERVICE_VERSION
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



