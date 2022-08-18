# calling aligner with os.system
import os
import subprocess
from pathlib import Path
import glob
import pysondb
from datetime import datetime

import os, time
import zipfile

    
def zipdir(path, ziph):
    # ziph is zipfile handle
    for root, dirs, files in os.walk(path):
        for file in files:
            ziph.write(os.path.join(root, file), 
                       os.path.relpath(os.path.join(root, file), 
                                       os.path.join(path, '..')))



# db
tasks_db = pysondb.getDb('../tasks_db.json')
bal_db = pysondb.getDb('../bal_db.json')

while True:
    time.sleep(4)
    sniffer_log = open("sniffer_log.error", "a+")
    try:
        tasks_to_execute = tasks_db.getBy({"task_status": "uploaded"})
    except Exception as e:
        now = datetime.now() # current date and time
        date_time = now.strftime("%m/%d/%Y, %H:%M:%S")
        sniffer_log.write(f"{date_time} :: {e}")

    for task in tasks_to_execute:
        try:
            corpus_folder = task["task_path"]
            get_output =  subprocess.Popen(f"mfa validate {corpus_folder} english english", shell=True, stdout=subprocess.PIPE).stdout
            res = get_output.read().decode("utf-8") 
            print(type(res))
            if "ERROR - There was an error in the run, please see the log." in res:
                print("The files are not in right format.")
                msg = "mfa validate >> The files are not in right format."
                now = datetime.now() # current date and time
                date_time = now.strftime("%m/%d/%Y, %H:%M:%S")
                sniffer_log.write(f"{date_time} :: {msg} :: {corpus_folder}")
            else:
                align_folder = f"{corpus_folder}_aligned"
                Path(align_folder).mkdir(parents=True, exist_ok=True)
                lang = task["lang"]
                print("lang is: ",lang)
                if lang == "da_DK": #Danish (da_DK)
                    o = subprocess.Popen(f"/home/nabil/nordalign/mfa10_test/beta2/montreal-forced-aligner/bin/mfa_align {corpus_folder} pretrained_models/dictionary_final.txt pretrained_models/Danish_Method2b.zip {align_folder}", shell=True, stdout=subprocess.PIPE).stdout.read().decode("utf-8")

                elif lang == "no_NO": #Norwegian Bokmål (no_NO)
                    o = subprocess.Popen(f"/home/nabil/nordalign/mfa10_test/beta2/montreal-forced-aligner/bin/mfa_align {corpus_folder} pretrained_models/dictionary_final.txt pretrained_models/no_NO.zip {align_folder}", shell=True, stdout=subprocess.PIPE).stdout.read().decode("utf-8")

                elif lang == "sv_SE": #Swedish (sv_SE)
                    o = subprocess.Popen(f"/home/nabil/nordalign/mfa10_test/beta2/montreal-forced-aligner/bin/mfa_align {corpus_folder} pretrained_models/dictionary_final.txt pretrained_models/sv_SE_201211.zip {align_folder}", shell=True, stdout=subprocess.PIPE).stdout.read().decode("utf-8")

                elif lang == "n_GB": #UK English (en_GB)
                    o = subprocess.Popen(f"/home/nabil/nordalign/mfa10_test/beta2/montreal-forced-aligner/bin/mfa_align {corpus_folder} pretrained_models/dictionary_final.txt pretrained_models/en_US_fromMFA.zip {align_folder}", shell=True, stdout=subprocess.PIPE).stdout.read().decode("utf-8")

                if "Error" in o:
                    now = datetime.now() # current date and time
                    date_time = now.strftime("%m/%d/%Y, %H:%M:%S")
                    sniffer_log.write(f"{date_time} :: {o} :: {corpus_folder}")
                elif "Done! Everything took" in o:
                    # success
                    try:
                        zip_file_name = f"zips/{task['user_id']}_{str(int(time.time()))}.zip"
                        with zipfile.ZipFile(zip_file_name, 'w', zipfile.ZIP_DEFLATED) as zipf:
                            zipdir(align_folder, zipf)
                        tasks_db.updateById(task["id"], {"task_status": "completed", "download_path": zip_file_name})
                        r = bal_db.getBy({'user_id': task['user_id']})
                        if len(r) == 0:
                            print("weird bug, balance db does not contain entry")
                        else:
                            pb = r[0]['balance']
                            db_id = r[0]['id']
                            bal_db.updateById(db_id, {'balance': pb - task["cost"]})
                            print("All success")
                            print("--------------------------------------------------")
                            now = datetime.now() # current date and time
                            date_time = now.strftime("%m/%d/%Y, %H:%M:%S")
                            sniffer_log.write(f"{date_time} :: All success :: {corpus_folder}")
                    except Exception as e:
                        now = datetime.now() # current date and time
                        date_time = now.strftime("%m/%d/%Y, %H:%M:%S")
                        sniffer_log.write(f"{date_time} :: {e}")

                else:
                    print("some unknown error")
                    now = datetime.now() # current date and time
                    date_time = now.strftime("%m/%d/%Y, %H:%M:%S")
                    sniffer_log.write(f"{date_time} :: {o} :: {corpus_folder}")
        except subprocess.CalledProcessError:
            # mfa align ~/mfa_data/my_corpus english english ~/mfa_data/my_corpus_aligned
            print("The files are not in right format.")

    sniffer_log.close()