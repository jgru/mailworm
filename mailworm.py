import os
import argparse
import shutil
from utils import *

from db_manager import MailDBManager
from mail import Mail


class MailWorm:

    REACTOR = "REACTOR"
    EXPORT = "EXPORT"
    DB_SUF = "sqlite"

    def __init__(self, inpath, outpath, caseno, is_legacy_geoip=False):
        print_sep()
        print(IMP_PFX + "Starting MailWorm")
        self.inpath = inpath
        self.outpath = outpath
        self.is_legacy_geoip = is_legacy_geoip

        if caseno is None:
            self.caseno = self.query_caseno()
        else:
            self.caseno = caseno

        self.output_dir, self.export_dir = self.create_output_dirs(outpath)

        # Create db
        self.db_path = os.path.join(self.output_dir, f"{self.caseno}.{self.DB_SUF}")
        self.db_manager = MailDBManager(self.db_path)

        # Parse input mails
        self.process_mails()

    def create_output_dirs(self, outpath):
        od = os.path.join(outpath, self.caseno)
        ed = os.path.join(outpath, self.caseno, self.EXPORT)

        '''
        if not os.path.exists(od):
            os.makedirs(od)
        else:
            print_sep()
            print(ALERT_PFX + "output directory {od} exists already. Exiting")
            exit()
        '''
        os.makedirs(ed, exist_ok=True)

        return od, ed

    def query_caseno(self):
        caseno = ""
        while not caseno != "":
            # Query file number for directory naming
            print(NOTE_PFX + "Please enter case no. in format [number-year] - e.g. 123456-2020")
            print_sep()
            caseno = input("File no.: ")
            caseno = caseno.replace("/", "_")
            print(NOTE_PFX + f"Writing to case directory: {caseno}")

        return caseno

    def process_mails(self):
        mails = []
        for root, dirs, files in os.walk(self.inpath):
            for filename in files:
                fp = os.path.join(root, filename)
                # Calc hash of source file
                hash = calc_hash(fp)

                if filename.endswith(".msg"):
                    msg = os.path.join(self.export_dir, f"{hash}.msg")
                    shutil.copyfile(fp, os.path.join(self.export_dir, f"{hash}.msg"))

                    eml_hash = hash + ".eml"
                    eml = os.path.join(self.export_dir, eml_hash)

                    msg2eml_cmd = [f"msgconvert", "--outfile", eml, msg]
                    exec_cmd(msg2eml_cmd)

                    m = Mail(eml, filename, is_legacy_geoip=self.is_legacy_geoip)
                    mails.append(m)

                elif filename.endswith(".eml"):
                    eml = os.path.join(self.export_dir, f"{hash}.eml")
                    shutil.copyfile(fp, eml)
                    m = Mail(eml, filename, is_legacy_geoip=self.is_legacy_geoip)
                    mails.append(m)

        self.db_manager.update_db(mails)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input-directory", required=True,
                        help="path to input directory")
    parser.add_argument("-o", "--output-directory", required=False, default="./",
                        help="path to output directory")
    parser.add_argument("-c", "--case-number", type=str, help="case no. for directory naming", required=False)
    parser.add_argument("-l", "--legacy-geoip", help="Specify '-l' to use legacy Geo IP DB (retrieve by installing geoip-bin)", required=False, default=False, action='store_true')
    args = parser.parse_args()

    m = MailWorm(args.input_directory, args.output_directory, args.case_number, is_legacy_geoip=args.legacy_geoip)
