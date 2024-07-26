
package com.subride

class PipelineLibraries implements Serializable {
    def script
    def envVars = [:]

    PipelineLibraries(script) {
        this.script = script
    }

    def setGlobalVariables(String serviceGroup, String serviceId, String version) {
        envVars.SERVICE_GROUP = serviceGroup
        envVars.SERVICE_ID = serviceId
        envVars.SERVICE_VERSION = version

        envVars.NFS_DIR = "data"
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
        envVars.IMAGE_REG_CREDENTIAL = "credential_cna_ondal"
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

    def prepareEnvironment() {
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
                                    //ssh -i \${SSH_KEY_FILE} \${SSH_USER}@${envVars.NFS_HOST} "sudo chmod -R 777 /${envVars.NFS_DIR}/${envVars.GRADLE_CACHE_DIR}/${envVars.SRC_DIR}"
                                fi
                                ssh -i \${SSH_KEY_FILE} \${SSH_USER}@${envVars.NFS_HOST} "sudo mkdir -p /${envVars.NFS_DIR}/${envVars.TRIVY_CACHE_DIR}/${envVars.SRC_DIR}"
                                //ssh -i \${SSH_KEY_FILE} \${SSH_USER}@${envVars.NFS_HOST} "sudo chmod -R 777 /${envVars.NFS_DIR}/${envVars.TRIVY_CACHE_DIR}/${envVars.SRC_DIR}"
                            """
                        }
                    }
                }
            }
        }
    }

    def setPodTemplates() {
        def volumes = [
            script.nfsVolume(mountPath: "/${envVars.TRIVY_CACHE_DIR}", serverAddress: "${envVars.NFS_HOST}", serverPath: "/${envVars.NFS_DIR}/${envVars.TRIVY_CACHE_DIR}/${envVars.SRC_DIR}", readOnly: false)
        ]
        
        if (envVars.SERVICE_GROUP == envVars.SERVICE_GROUP_SC || envVars.SERVICE_GROUP == envVars.SERVICE_GROUP_SUBRIDE) {
            volumes.add(
                script.nfsVolume(mountPath: "/home/gradle/.gradle", serverAddress: "${envVars.NFS_HOST}", serverPath: "/${envVars.NFS_DIR}/${envVars.GRADLE_CACHE_DIR}/${envVars.SRC_DIR}", readOnly: false)
            )
        }
        
        script.podTemplate(
            label: "${envVars.PIPELINE_ID}",
            containers: [
                script.containerTemplate(name: "trivy", image: "aquasec/trivy", ttyEnabled: true, command: "cat"),
                script.containerTemplate(name: "kubectl", image: "lachlanevenson/k8s-kubectl", command: "cat", ttyEnabled: true),
                script.containerTemplate(name: "gradle", image: "gradle:jdk17", ttyEnabled: true, command: "cat"),
                script.containerTemplate(name: 'podman', image: "mgoltzsche/podman", ttyEnabled: true, command: 'cat', privileged: true),
                script.containerTemplate(name: 'envsubst', image: "hiondal/envsubst", command: 'sleep', args: '1h')
            ],
            volumes: volumes
        )    
    }

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
            script.echo "No changes in <${envVars.SRC_DIR}> directory. Skipping pipeline."
            script.currentBuild.result = 'STOP'
            return false
        }

        return true
    }

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

    def stageBuildJar() {
        script.stage("Build Jar") {
            script.container("gradle") {
                script.sh 'echo "Build jar under build directory"'
                script.sh "gradle :${envVars.SRC_DIR}:${envVars.SUB_DIR_INFRA}:build -x test"
            }
        }    
    }

    def stageBuildScripts() {
        script.stage("Build React Scripts") {
            script.container("node") {
                script.sh """
                    npm install
                    npm run build --watch --watch-options-aggregate-timeout 1000
                """
            }
        }
    }

    def stageSonarQubeAnalysisForJava() {
        def javaBinaries = getJavaBinaries()

        script.stage("SonarQube Analysis") {
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
    }

    def getJavaBinaries() {
        if (envVars.SERVICE_GROUP == envVars.SERVICE_GROUP_SUBRIDE) {
            return "${envVars.SUB_DIR_INFRA}/build/classes/java/main,${envVars.SUB_DIR_BIZ}/build/classes/java/main"
        } else {
            return "build/classes/java/main"
        }
    }

    def stageSonarQubeAnalysisForScripts() {
        script.stage("SonarQube Analysis") {
            script.container("sonar-scanner") {
                script.withSonarQubeEnv("${envVars.SONAR_SERVER_ID}") {
                    script.sh """
                        sonar-scanner
                    """
                }
            }    
        }
    }

    def stageVerifyQualityGate() {
        script.stage("Verify Quality Gate") {
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
    }

    def stageBuildContainerImageForJava() {
        def buildDir = getBuildDir()
        script.stage("Build Container image") {
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
    }

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

    def stageBuildContainerImageForScripts() {
        script.stage("Build Container image") {
            script.container("podman") {
                script.withCredentials([script.usernamePassword(
                    credentialsId: "${envVars.IMAGE_REG_CREDENTIAL}",
                    usernameVariable: 'USER',
                    passwordVariable: 'PASSWORD'
                )]) {
                    script.sh """
                        echo user "\$USER" pasword "\$PASSWORD"
                        podman login ${envVars.IMAGE_REG_HOST} --username \${USER} --password \${PASSWORD}
                        podman build -f ${envVars.baseDir}/Dockerfile \
                            -t ${envVars.imagePath}:${envVars.tag} \
                            .
                        podman push ${envVars.imagePath}:${envVars.tag}

                        podman tag ${envVars.imagePath}:${envVars.tag} ${envVars.imagePath}:latest
                        podman push ${envVars.imagePath}:latest
                    """
                }
            }
        }
    }

    def stageScanContainerImageVulnurability() {
        script.stage("Scan Image Vulnerability") {
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
    }

    def stagePushContainerImage() {
        script.stage("Push Container image") {
            script.container("podman") {
                script.withCredentials([script.usernamePassword(
                    credentialsId: "${envVars.IMAGE_REG_CREDENTIAL}",
                    usernameVariable: 'USER',
                    passwordVariable: 'PASSWORD'
                )]) {
                    script.sh """
                        echo user "$USER" pasword "$PASSWORD"
                        podman login ${envVars.IMAGE_REG_HOST} --username ${USER} --password ${PASSWORD}
                        podman push ${envVars.imagePath}:${envVars.tag}

                        podman tag ${envVars.imagePath}:${envVars.tag} ${envVars.imagePath}:latest
                        podman push ${envVars.imagePath}:latest
                    """
                }
            }
        }
    }

    def stageGenerateManifest() {
        script.stage("Generate deployment yaml") {
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
    }

    def stageDeploy() {
        script.stage("Deploy") {
            script.container("kubectl") {
                script.sh "kubectl apply -f ${envVars.baseDir}/${envVars.manifest} -n ${envVars.namespace}"
            }
        }    
    }

    def notifySlack(STATUS, COLOR) {
        // Implement Slack notification logic here
        // For example:
        // script.slackSend(channel: '#cicd', color: COLOR, message: STATUS + " : " + "${script.env.JOB_NAME} [${script.env.BUILD_NUMBER}] (${script.env.BUILD_URL})")
    }

    def getImageTag() {
        def dateFormat = new java.text.SimpleDateFormat("yyyyMMddHHmmss")
        def currentDate = new Date()
        def timestamp = dateFormat.format(currentDate)

        return envVars.SERVICE_VERSION
    }

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