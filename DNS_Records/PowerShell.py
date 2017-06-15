import subprocess
import os

POWERSHELL_DIR = os.path.dirname(os.path.realpath(__file__))


def export_cert_chain(base64cert, export_filename):
    p = subprocess.Popen([r'powershell.exe',
                          '-ExecutionPolicy', 'Unrestricted',
                          r'.\Export-CertChain.ps1',
                          '-Base64Cert', base64cert,
                          '-ExportFilename', '"'+export_filename+'.p7b"'],
                         cwd=POWERSHELL_DIR)
    result = p.wait()
    return result
