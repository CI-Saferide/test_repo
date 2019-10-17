node('AI_Build'){    

    // clean work-space
    cleanWs deleteDirs: true

    //get tinestamp
    def now = new Date()
    env.TIME=now.format("yyyyMMdd-HH:mm:ss.SSS", TimeZone.getTimeZone('UTC'))

    if ("${params.trigger_type}" != "null" && "${params.trigger_type}" != ""){
        echo "triggerd event from ${params.trigger_type}"
        env.TRIGGER_TYPE="${params.trigger_type}"
    }else{
        // env.TRIGGER_TYPE=//TODO
        env.TRIGGER_TYPE='master'
    }
    env.VOLUME = "/home/build/ai"

    //run inside docker
    docker.image("192.168.1.8:8084/ai_images/ai-docker:latest").inside("--cap-add=NET_ADMIN --entrypoint='' --privileged -u 0:0 -v ${VOLUME}:${VOLUME} ") {
        
            stage('Init'){
                echo "### Init ###"

                //clone source code
                checkout([$class: 'GitSCM', branches: [[name: '*/master']],
                doGenerateSubmoduleConfigurations: false,
                extensions: [],
                submoduleCfg: [],
                userRemoteConfigs: [[credentialsId: 'CI_user', url: 'https://github.com/saferide-tech/algo.git']]])
                env.SHORT_HASH = sh(script: 'git rev-parse --short HEAD',returnStdout: true ).trim()

                runCommand("pip install --force-reinstall ${WORKSPACE}/sfr_utils ")
            }// end of stage init
            // pre step for getting devops tools
            get_devops_tools()

        if(params.ETL){
            stage('Preprocess Data'){
                stage('Running can_to_rides'){
                    echo "### Running can_to_rides ###"
                    // this creates the ride-files in a local directory, /ride_files/, so the originals on <host-volume> are not damaged

                    runCommand("mkdir ${WORKSPACE}/ride_files")
                    dir("${WORKSPACE}/can_etl"){
                        runCommand("python3 can_to_rides.py --input_path ${VOLUME}/candata/train_data/zoe_not_attacked --destination ${WORKSPACE}/ride_files/zoe_not_attacked_can1 --config_file_path ${WORKSPACE}/projects/Renault/can1_can_config_can_to_rides.json")
                    }
                    // compaing gate for ride_files
                    get_devops_tools()
                    compare_res_status = compare_results("${VOLUME}/ride_files/zoe_not_attacked_can1" , "${WORKSPACE}/ride_files/zoe_not_attacked_can1" )
                    if (compare_res_status != 0 ) {
                        msg = "[ COMPARING ERROR ] in ride_files part"
                        currentBuild.result = 'FAILURE'
                        emailExt()
                        error(msg)
                    }
                }// end of stage Running can_to_rides

                stage('Running rides_to_mids'){
                    echo "### Running rides_to_mids ###"
                    //this creates the mid-files in a local directory, /mid_files/, so the originals on <host-volume> are not damaged, but still takes the input files from <host-volume>

                    runCommand("mkdir ${WORKSPACE}/mid_files")
                    dir("${WORKSPACE}/can_etl"){
                            runCommand("python3 rides_to_mids.py --input_path ${VOLUME}/ride_files/zoe_not_attacked_can1 --destination ${WORKSPACE}/mid_files/zoe_not_attacked_can1")
                    }
                    // compaing gate for ride_files
                    get_devops_tools()
                    compare_res_status = compare_results("${VOLUME}/mid_files/zoe_not_attacked_can1" , "${WORKSPACE}/mid_files/zoe_not_attacked_can1" )
                    if (compare_res_status != 0 ) {
                        msg = "[ COMPARING ERROR ] in mid_files part"
                        currentBuild.result = 'FAILURE'
                        emailExt()
                        error(msg)
                    }
                }// end of stage Running rides_to_mids
            }// end of stage Preprocess Data
        }
        if(params.Train){
            stage('Train'){
                stage('Train on mids'){
                    echo "### Creating mid-models ###"
                    // running the pipeline for creating the mid-models for can1:

                    runCommand("mkdir ${WORKSPACE}/results")

                    dir("${WORKSPACE}/pipeline"){
                        runCommand("python3 main.py --config_file_path ${WORKSPACE}/projects/Renault/can1_MID_train_config.json --process_subfields False --subfields_file_path ${WORKSPACE}/projects/Renault/Zoe_can1_Subfields.csv --rides_files_path ${VOLUME}/ride_files/zoe_not_attacked_can1/ --mids_files_path ${VOLUME}/mid_files/zoe_not_attacked_can1/ --output_path ${WORKSPACE}/results/zoe_not_attacked_can1_mids/ --overwrite")
                    }
                    // compaing gate for ride_files
                    get_devops_tools()
                    compare_res_status = compare_results("${VOLUME}/models/can1/" , "${WORKSPACE}/results/zoe_not_attacked_can1_mids/" )
                    if (compare_res_status != 0 ) {
                        msg = "[ COMPARING ERROR ] in ride_files part"
                        currentBuild.result = 'FAILURE'
                        emailExt()
                        error(msg)
                    }
                }// end of stage Creating mid-models
        
                stage('Train on variables'){
                    echo "### Creating variable-models ###"
                    // Running the pipeline for creating the variable-models for can1:
                    dir("${WORKSPACE}/pipeline"){
                        runCommand("python3 main.py --config_file_path ${WORKSPACE}/projects/Renault/can1_variables_train_config.json --process_subfields True --subfields_file_path ${WORKSPACE}/projects/Renault/Zoe_can1_Subfields.csv --rides_files_path ${VOLUME}/ride_files/zoe_not_attacked_can1/  --mids_files_path ${VOLUME}/mid_files/zoe_not_attacked_can1/ --output_path ${WORKSPACE}/results/zoe_not_attacked_can1_variables --overwrite")
                    }
                }// end of stage Creating variable-models
            }// end of stage Train
        }

        if(params.Inference){
            stage('inference'){
                echo "### Running inference (test) ###"
                // Running the inference (test):

                runCommand("mkdir ${WORKSPACE}/results/anomalies")

                dir("${WORKSPACE}/renault_test_pipeline"){
                    runCommand("python3 test_batch.py --config_file_path ${WORKSPACE}/projects/Renault/test_config.json --collector_files_path ${VOLUME}/candata/zoe_out_of_sample  --alerts_file_path ${WORKSPACE}/results/anomalies/zoe_out_of_sample.log --models_path 1 ${VOLUME}/models/can1 --models_path 2 ${VOLUME}/models/can2 --process_subfields True")
                }
            }// end of stage Inference
        }
        
    }//end run inside docker
  
    emailExt()
}// end of node('build')

//this method send email with build result
def emailExt () {
     emailext (body: '''${SCRIPT, template="buildlog.template"}''',
        mimeType: 'text/html',
        subject: "[Jenkins] - Build ${currentBuild.currentResult}",
        to: "${ai_MailRecipients}",
        replyTo: "${ai_MailRecipients}",
        recipientProviders: [[$class: 'CulpritsRecipientProvider']])

 } 

// this method run shell command with ascii plugin
def runCommand ( command ) {
    ansiColor('xterm'){
        if(isUnix()){
        sh command
        } else {
            bat command
        }
    }
} 

// this method run bash command with ascii plugin
def runCommandBash ( command ) {
    sh "#!/bin/bash \n" +
        command
}

def compare_results(dir_a,dir_b){
    def statusCode = sh script:"${DEVOPS_DIR}/tools/AI_tools/compare/comparing.py "+dir_a + " " + dir_b , returnStatus:true
    return(statusCode)
}


    
//example:runCommand (" ${DEVOPS_DIR}/tools/upload_to_nexus '$Username' '$Password' 'libcompress.a' 'megican' '$SHORT_HASH' ")
def uploadToNexus (artifact, product, hash, platform ) {
    // upload artifact to nexus using cerd plugin
    withCredentials([usernamePassword(credentialsId: 'Nexus', passwordVariable: 'Password', usernameVariable: 'Username')]) {
        if ("${TRIGGER_TYPE}" == "tag"){
            runCommand (" ${DEVOPS_DIR}/tools/upload_to_nexus '$Username' '$Password' " +artifact+ " " +product+ " " +hash+ " " + platform )
        }else if ("${TRIGGER_TYPE}" == "master"){
            hash=hash+"-master"
            runCommand (" ${DEVOPS_DIR}/tools/upload_to_temp_nexus '$Username' '$Password' " +artifact+ " " +product+ " " +hash+ " " + platform )
        }
    }      
}
//  method for getting devops tool
def get_devops_tools(){
    if(!fileExists("devops_tools")){
        runCommand('mkdir devops_tools')   
    }
    runCommand('chown 1000:1000 devops_tools') 

    dir('devops_tools'){
        if(!fileExists("tools")){   
            // getting tools dir
            checkout([$class: 'GitSCM', branches: [[name: '*/master']],
            doGenerateSubmoduleConfigurations: false,
            extensions: [[$class: 'SparseCheckoutPaths', ]],
            submoduleCfg: [],
            userRemoteConfigs: [[credentialsId: 'CI_user', url: 'https://github.com/saferide-tech/CI.git']]])
        }
        env.DEVOPS_DIR = sh(script: 'pwd',returnStdout: true ).trim()
    }
}
