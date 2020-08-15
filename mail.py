import datetime
import os
import email.parser
import json
import eml_parser  # Government CERT LU
import email
import mimetypes
import geoip2.database
from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from email.policy import default
from dateutil import parser as dtparser
from netaddr import IPAddress
from ipwhois import IPWhois
from hachoir.metadata import extractMetadata
from hachoir.parser import createParser
import pygeoip  # uses standard dbs of geoip-bin (apt install geoip-bin)

Base = declarative_base()


class Mail(Base):
    __tablename__ = "reactordata"

    id = Column(Integer, primary_key=True)
    input_name = Column('INPUT_MAILNAME', String)
    hash = Column('HASH', String)
    json_name = Column('CONVERTED_NAME', String)
    date_raw = Column('DATE_RAW', String)
    date_iso = Column('DATE_ISO', DateTime)
    timestamp = Column('TIMESTAMP', String)
    from_field = Column('MAIL_FROM', String)
    to_field = Column('MAIL_TO', String)
    subject = Column('SUBJECT', String)
    in_reply_to = Column('IN_REPLY_TO', String)
    msgid = Column('MESSAGE_ID', String)
    references = Column('REFERENCES', String)
    user_agent = Column('USER_AGENT', String)
    recv_ips = Column('RECEIVED_IP_LIST', String)
    recv_srvs = Column('RECEIVED_SERVER_LIST', String)
    recv_srv_first = Column('FIRST_RECEIVED_SERVER', String)
    recv_ip_first = Column('FIRST_RECEIVED_EXTERN_IP', String)
    recv_ip_geo = Column('FIRST_EXTERN_GEOCODE', String)
    recv_ip_whois_name = Column('FIRST_EXTERN_WHOIS_NAME', String)
    recv_ip_whois_desc = Column('FIRST_EXTERN_WHOIS_DESC', String)
    xorgip = Column('X_ORIGIN_IP', String)
    xorgip_whois_name = Column('X_ORIGIN_IP_WHOIS_NAME', String)
    xorgip_whois_desc = Column('X_ORIGIN_IP_WHOIS_DESC', String)
    xorgip_geo = Column('X_ORIGIN_IP_GEOCODE', String)
    attachments = Column('ATTACHMENTS', String)
    attachments_metadata= Column('ATTACHMENT_METADATA', String)

    GEO_DB = "./geoip/GeoIP2-City.mmdb"
    GEO_DB4 = "/usr/share/GeoIP/GeoIP.dat"
    GEO_DB6 = "/usr/share/GeoIP/GeoIPv6.dat"

    def __init__(self, filepath, orig_name, is_legacy_geoip=False):
        """
        Constructs a Mail-object from a given .eml-file. First .eml is read  and converted to json then it will
        :param filepath:
        """
        parsed_eml = self.to_json(filepath)

        self.filepath = filepath
        self.is_legacy_geoip = is_legacy_geoip
        self.input_name = orig_name
        self.json_name = os.path.basename(filepath)
        self.hash = os.path.basename(filepath).rsplit(".")[0]

        if not is_legacy_geoip:  # Use current MaxMind DBs
            self.geoip_reader = geoip2.database.Reader(self.GEO_DB)
        else:  # Use databases of geoip-bin under /usr/share/GeoIP
            self.geoip_reader = (pygeoip.GeoIP(self.GEO_DB4), pygeoip.GeoIP(self.GEO_DB6))

        with open(f"{filepath.rsplit('.', 1)[0]}.json", "w") as d:
            json_dump = json.dumps(parsed_eml, default=self.json_serial)
            d.write(json_dump)

        self.recv_srv_list, self.recv_ip_list = self.retrieve_mtas(parsed_eml)
        self.recv_srvs = str(self.recv_srv_list)
        self.recv_ips = str(self.recv_ip_list)

        self.recv_ip_first = None
        extern_ips = self.find_extern(self.recv_srv_list, self.recv_ip_list)

        if len(extern_ips) > 0:
            self.recv_ip_first = extern_ips[0]

        if self.recv_ip_first is not None and self.is_public_ip(self.recv_ip_first):
            self.recv_ip_whois_name, self.recv_ip_whois_desc = self.get_whois_ip(self.recv_ip_first)
            city_country_tuple = self.lookup_geoip(self.recv_ip_first)
            # Ignore None entries
            self.recv_ip_geo = ", ".join(item if item else "" for item in city_country_tuple)

        self.date_raw, self.date_iso, self.timestamp = self.retrieve_ts(parsed_eml)
        self.from_field = self.retrieve_header_field(parsed_eml, "from")
        self.to_field = self.retrieve_header_field(parsed_eml, "to")
        self.subject = self.retrieve_header_field(parsed_eml, "subject")

        self.xorgip = self.retrieve_header_field(parsed_eml, 'x-originating-ip')

        #self.xorgip_whois_name = ""
        #self.xorgip_whois_desc = ""
        #self.xorgip_geo = ""

        if self.xorgip is not None:
            self.xorgip = self.xorgip.replace("[", "").replace("]", "")
            if self.is_public_ip(self.xorgip):
                self.xorgip_whois_name, self.xorgip_whois_desc = self.get_whois_ip(self.xorgip)
                self.xorgip_geo = ", ".join(self.lookup_geoip(self.xorgip))

        self.msgid = self.retrieve_header_field(parsed_eml, "message-id")
        self.in_reply_to = self.retrieve_header_field(parsed_eml, "in-reply-to")
        self.references = self.retrieve_header_field(parsed_eml, "references")
        self.user_agent = self.retrieve_header_field(parsed_eml, "user-agent")

        attached_files, metadata = self.extract_attachments()

        self.attachments = str(attached_files)
        self.attachments_metadata = str(metadata)

    @staticmethod
    def json_serial(obj):
        if isinstance(obj, datetime.datetime):
            serial = obj.isoformat()
            return serial

    def to_json(self, filepath):
        with open(filepath, 'rb') as f:
            raw_mail = f.read()
            ep = eml_parser.EmlParser()
            parsed_eml = ep.decode_email_bytes(raw_mail)

        return parsed_eml

    def lookup_geoip(self, ip):
        if self.is_legacy_geoip:
            return self.lookup_geoip_legacy(ip)

        response = self.geoip_reader.city(ip)
        return response.city.name, response.country.iso_code

    def lookup_geoip_legacy(self, ip):
        # library is based on Maxmind’s GeoIP C API.
        if IPAddress(ip).version == 4:
            # print(geoip_reader[0].country_code_by_addr(ip))
            return self.geoip_reader[0].country_code_by_addr(ip)
        elif IPAddress(ip).version == 6:
            # print(geoip_reader[0].country_code_by_addr(ip))
            return self.geoip_reader[0].country_code_by_addr(ip)

        return None

    @staticmethod
    def is_public_ip(ip):
        ip_obj = IPAddress(ip)
        if not ip_obj.is_private() and not ip_obj.is_reserved():
            return True
        return False

    @staticmethod
    def get_whois_ip(ip):
        whois_names = []
        whois_descs = []

        obj = IPWhois(ip)
        results = obj.lookup_whois(get_referral=True)

        try:
            for dict in results['nets']:
                SHORT_WHOIS_NAME_X = (dict['name'])
                if SHORT_WHOIS_NAME_X is not None:
                    whois_names.append(SHORT_WHOIS_NAME_X)
                    # print("whois_names: ", whois_names)

                SHORT_WHOIS_DESCRIPTION_X = (dict['description'])
                if SHORT_WHOIS_DESCRIPTION_X is not None:
                    whois_descs.append(SHORT_WHOIS_DESCRIPTION_X)
                    # print("SHORT_WHOIS_DESCRIPTION_LIST_X: ", whois_descs)
        except:
            whois_names = "UNKNOWN"
            whois_descs = "UNKNOWN"
            pass

        whois_names = str(whois_names)
        whois_descs = str(whois_descs)

        return whois_names, whois_descs

    @staticmethod
    def retrieve_header_field(json, key):
        if key in json['header']['header'].keys():
            for val in json['header']['header'][key]:
                return val

    @staticmethod
    def find_extern(recv_srvs, recv_ips):
        recv_srvs.reverse()
        extern_list = []

        for s in recv_srvs:
            for i in s:
                # print(i)
                for rip in recv_ips:
                     if rip == i:
                         if not IPAddress(i).is_private():
                             extern_list.append(i)
        return extern_list

    @staticmethod
    def retrieve_mtas(eml_json):
        recv_srvs = []

        for field in eml_json['header']['received']:
            try:
                recv_srv = field['from']
                recv_srvs.append(recv_srv)

            except:
                pass

        recv_ips = []

        try:
            for val in eml_json['header']['received_ip']:
                # print("Received-IP: " + val)
                recv_ips.append(val)
        except Exception as e:
            print(e)
            pass

        return recv_srvs, recv_ips

    @staticmethod
    def retrieve_ts(eml_json):
        rawdate = eml_json['header']['header']['date'][0]
        isodate = dtparser.parse(rawdate)
        timestamp = datetime.datetime.timestamp(isodate)

        return rawdate, isodate, timestamp

    def extract_attachments(self):
        attach_dir = os.path.join(os.path.dirname(self.filepath), self.hash)
        if not os.path.exists(attach_dir):
            os.mkdir(attach_dir)
        attachments = []
        md = []
        with open(self.filepath, 'rb') as fp:
            msg = email.message_from_binary_file(fp, policy=default)

            counter = 1
            for part in msg.walk():
                # multipart/* are just containers
                if part.get_content_maintype() == 'multipart':
                    continue
                # Applications should really sanitize the given filename so that an
                # email message can't be used to overwrite important files
                filename = part.get_filename()

                if not filename:
                    ext = mimetypes.guess_extension(part.get_content_type())
                    if not ext:
                        # Use a generic bag-of-bits extension
                        ext = '.bin'
                    filename = f'part-{counter:03d}{ext}'
                counter += 1
                apath = os.path.join(attach_dir, filename)

                with open(apath, 'wb') as fp:
                    fp.write(part.get_payload(decode=True))

                # Keep track of found attachments
                if not filename.startswith("part"):
                    attachments.append(apath)
                    md.append(self.get_metadata(apath)) #part.get_payload(decode=True))

        return attachments, md

    @staticmethod
    def get_metadata(fp):
        parser = createParser(fp)

        # Make sure, a parser was found
        if not parser:
            print(f"Could not find parser for {fp}")
            # Return none, if plaintext or otherwise unsupported
            return ""

        # Read metadata with selected parser
        with parser:
            try:
                metadata = extractMetadata(parser)
            except Exception as err:
                print(f"Metadata extraction error: {err}")
                metadata = None

        metadata_str = ""

        if metadata:
            for line in metadata.exportPlaintext():
                metadata_str += f"{line}\n"

        return metadata_str
