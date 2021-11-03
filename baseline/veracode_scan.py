from ..core import hooks

from ..utils import logger_config
from ..core.utils import (
    print_script_start,
    print_script_end,
    run_command_with_output,
    step_filter,
)
from ..core.workspace_adapters.workspace_adapter_retriever import get_workspace_adapter
from ..core.workspace_adapters.canaveral_workspace_adapter import (
    CanaveralWorkspaceAdapter,
)

import tempfile
import docker
import logging
import os
import requests
from pathlib import Path

logger_config.configure_logging()
logger = logging.getLogger(__name__)


def _get_scan_branch_tag(workspace_adapter: CanaveralWorkspaceAdapter):
    branch = workspace_adapter.branch
    branch = branch.replace("master", "prod")
    branch = branch.replace("mainline", "prod")
    branch = branch.replace("main", "prod")
    branch = branch.replace("pull/", "pre-merge/")
    branch = branch.replace("pr/", "pre-merge/")

    return branch


def initiate_scan():
    print_script_start(__file__)
    hooks.run_hooks(__file__, "init")

    veracode_opts = []
    veracode_targets = []

    if os.environ.get("ENABLE_SECURITY_SCAN", "0") != "1":
        logger.info(
            "Security scan was not enabled, try setting ENABLE_SECURITY_SCAN=1 if wanted"
        )
        return False, False, False

    logger.info("Security scan enabled, running")
    logger.info("Setting up BRANCH_TAG, VERSION, and PROJECT")

    workspace_adapter = get_workspace_adapter()

    scan_branch_tag = _get_scan_branch_tag(workspace_adapter)
    version = f"{scan_branch_tag}:{workspace_adapter.build_identifier}"
    project = f"{workspace_adapter.org}/{workspace_adapter.repo}"

    logger.info(
        f"Setup scan branch tag as {scan_branch_tag} and version: {version}, project: {project}"
    )

    if "VERACODE_API_ID" in os.environ:
        veracode_api_id = (os.environ["VERACODE_API_ID"])
        print("VERACODE_API_ID="+veracode_api_id)
    else:
        print("VERACODE_API_ID not set, exiting...")
        return False, False, False

    if "VERACODE_API_KEY" in os.environ:
        veracode_api_key = (os.environ["VERACODE_API_KEY"])
        print("VERACODE_API_KEY="+veracode_api_key)
    else:
        print("VERACODE_API_KEY not set, exiting...")
        return False, False, False

    if "VERACODE_TARGETS" in os.environ:
        veracode_targets = (os.environ["VERACODE_TARGETS"]).split()
        print("VERACODE_TARGETS="+str(veracode_targets))
    else:
        print("VERACODE_TARGETS not set, exiting...")
        return False, False, False
        
    cmd = "mkdir /tmp/veracode.pipeline; cd /tmp/veracode.pipeline; wget https://downloads.veracode.com/securityscan/pipeline-scan-LATEST.zip; unzip pipeline-scan-LATEST.zip; cd -"
    cmd = "mkdir -p /tmp/veracode.pipeline; rm -rf /tmp/veracode.pipeline/*; cd /tmp/veracode.pipeline; wget https://downloads.veracode.com/securityscan/pipeline-scan-LATEST.zip; unzip pipeline-scan-LATEST.zip; cd -"
    print("Executing:"+cmd)
    os.system(cmd)

    for target in veracode_targets:
        print("Veracode scanning target="+target)
        #
        # First colon in a target is used to divide target file and findings file
        #
        colonIdx = target.find(":")
        if colonIdx < 0:
            print("Target:"+target+" missing delimiter ':' to delimit target file and findings file, exiting...")
            exit(4)
        targetfile = target[0:colonIdx]
        print("targetfile="+targetfile)
        baselineIdx = target.find(":",colonIdx+1)
        #
        # Second, optional colon is used to delimit findings file and baselineUrl
        #
        if baselineIdx > 0:
            baselineUrl = target[baselineIdx+1:]
            findings = target[colonIdx+1:baselineIdx]
            print("findings="+findings)
            print("baselineUrl="+baselineUrl)
            #
            # Use baselineUrl's basename to create baseline file
            #
            baselineBasename=os.path.basename(baselineUrl)
            jsonIdx = baselineBasename.rfind(".json")
            if jsonIdx >= 0:
                baselineBasename = baselineBasename[0:jsonIdx+5]
            cmd = "wget "+baselineUrl+" -O/tmp/veracode.pipeline/" + baselineBasename
            print("Executing:"+cmd)
            os.system(cmd)
            cmd = "java -jar /tmp/veracode.pipeline/pipeline-scan.jar --veracode_api_id " + veracode_api_id + " --veracode_api_key " + veracode_api_key + " --file " + targetfile + " -jf " + findings + " -bf /tmp/veracode.pipeline/" + baselineBasename
            print("Executing:"+cmd)
            os.system(cmd)
        else:
            findings = target[colonIdx+1:]
            print("findings="+findings)
            cmd = "java -jar /tmp/veracode.pipeline/pipeline-scan.jar --veracode_api_id " + veracode_api_id + " --veracode_api_key " + veracode_api_key + " --file " + targetfile + " -jf " + findings
            print("Executing:"+cmd)
            os.system(cmd)
        cmd = "cp "+findings+" /tmp/canaveral_logs"
        print("Executing:"+cmd)
        os.system(cmd)

    return veracode_api_id, veracode_api_key, veracode_targets

if __name__ == "__main__":
    initiate_scan()
