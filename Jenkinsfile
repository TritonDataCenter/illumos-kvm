/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2020 Joyent, Inc.
 */

@Library('jenkins-joylib@v1.0.4') _

pipeline {

    agent {
        label 'platform:true && image_ver:18.4.0 && pkgsrc_arch:x86_64 && ' +
            'dram:8gb && !virt:kvm && fs:pcfs && fs:ufs && jenkins_agent:2'
    }

    options {
        buildDiscarder(logRotator(numToKeepStr: '30'))
        timestamps()
        parallelsAlwaysFailFast()
    }

    stages {
        stage('trigger smartos-live') {
            when {
                anyOf {
                    branch 'master'
                    triggeredBy cause: 'UserIdCause'
                }
                // Prevent a user from starting a UserIdCause build on a
                // release branch, since that would trigger the smartos-live
                // 'master' branch build below, which is not what we want.
                not {
                    branch pattern: 'release-\\d+', comparator: 'REGEXP'
                }
            }
            steps {
                build(job:'joyent-org/smartos-live/master',
                    wait: false,
                    parameters: [
                        text(name: 'CONFIGURE_PROJECTS',
                            value:
                            "illumos-extra: master: origin\n" +
                            'illumos: master: origin\n' +
                            'local/kbmd: master: origin\n' +
                            'local/kvm-cmd: master: origin\n' +
                            'local/kvm: $BRANCH_NAME: origin\n' +
                            'local/mdata-client: master: origin\n' +
                            'local/ur-agent: master: origin')
                    ])
            }
        }
    }
    post {
        always {
            joyMattermostNotification(channel: 'jenkins')
        }
    }
}
