#!/usr/bin/python

import email
import sys
import shutil
import hashlib
import os
from os import listdir
from os.path import isfile, join
from email.Header import decode_header
from base64 import b64decode
from email.Parser import Parser as EmailParser
from email.utils import parseaddr
from StringIO import StringIO
import traceback
from bs4 import BeautifulSoup
import re
from sets import Set
import quopri, base64

'''
Adjust paths to suit your environment

Note that the PAYLOADDIR should match that in runvt.py

'''
SPAMDIR = '/home/foo/.Spam/cur'
PAYLOADDIR = '/home/foo/malware'
filelist = []
fl = [f for f in listdir(SPAMDIR) if isfile(join(SPAMDIR,f))]
for item in fl:
  filelist.append(join(SPAMDIR,item))






def decode_quote_printable_part(quo_pri_part):
        """
        Decodes a quote-printable encoded MIME object
        :param quo_pri_part: MIME msg part
        :return: decoded text, null if exception
        """
        try:
            quo_pri_payload = quo_pri_part.get_payload()
            return quopri.decodestring(quo_pri_payload)
        except Exception as err:
            print "ERROR - Exception when decoding quoted printable: %s" % err
            return ""

def decode_base64_part(base64_part):
        """
        Decodes base64 encoded MIME object
        :param base64_part: MIME msg part
        :return: decoded text, null if exception
        """
        try:
            decoded_part = base64.b64decode(base64_part)
            return decoded_part
        except Exception as err:
            print "ERROR - Exception when decoding base64 part: %s" % err
            return ""

def get_urls_from_html_part(html_code):
        """
        Parses the given HTML text and extracts the href links from it.
        The input should already be decoded
        :param html_code: Decoded html text
        :return: A list of href links (includes mailto: links as well), null list if exception
        """
        try:
            soup = BeautifulSoup(html_code)
            html_urls = []
            for link in soup.findAll("a"):
                url = link.get("href")
                if url and "http" in url:
                    html_urls.append(url)
            return html_urls
        except Exception as err:
            print "ERROR - Exception when parsing the html body: %s" % err
            return []

def get_urls_from_plain_part(email_data):
        """
        Parses the given plain text and extracts the URLs out of it
        :param email_data: plain text to parse
        :return: A list of URLs (deduplicated), a null list if exception
        """
        try:
            pattern = "abcdefghijklmnopqrstuvwxyz0123456789./\~#%&()_-+=;?:[]!$*,@'^`<{|\""
            indices = [m.start() for m in re.finditer('http://', email_data)]
            indices.extend([n.start() for n in re.finditer('https://', email_data)])
            urls = []
            if indices:
                if len(indices) > 1:
                    new_lst = zip(indices, indices[1:])
                    for x, y in new_lst:
                        tmp = email_data[x:y]
                        url = ""
                        for ch in tmp:
                            if ch.lower() in pattern:
                                url += ch
                            else:
                                break
                        urls.append(url)
                tmp = email_data[indices[-1]:]
                url = ""
                for ch in tmp:
                        if ch.lower() in pattern:
                            url += ch
                        else:
                            break
                urls.append(url)
                urls = list(Set(urls))
                return urls
            return []

        except Exception as err:
            print "ERROR - Exception when parsing plain text for urls: %s" % err
            return []

def get_urls_list(msg):
        """
        Collects all the URLs from an email
        :param msg: email message object
        :return: A dictionary of URLs => final_urls = {'http': [], 'https': []}
        """
        urls = []
        for part in msg.walk():
            decoded_part = part.get_payload()
            if part.__getitem__("Content-Transfer-Encoding") == "quoted-printable":
                decoded_part = decode_quote_printable_part(part)
            elif part.__getitem__("Content-Transfer-Encoding") == "base64":
                decoded_part = decode_base64_part(part.get_payload())
            if part.get_content_subtype() == "plain":
                urls.extend(get_urls_from_plain_part(decoded_part))
            elif part.get_content_subtype() == "html":
                urls.extend(get_urls_from_html_part(decoded_part))

        final_urls = {'http': [], 'https': []}
        for url in urls:
            if "http://" in url:
                final_urls['http'].append(url)
            else:
                final_urls['https'].append(url)
        return final_urls










class NotSupportedMailFormat(Exception):
    pass

def parse_attachment(message_part):
    content_disposition = message_part.get("Content-Disposition", None)
    if content_disposition:
        dispositions = content_disposition.strip().split(";")
        if bool(content_disposition and dispositions[0].lower() == "attachment"):

            file_data = message_part.get_payload(decode=True)
            attachment = StringIO(file_data)
            attachment.content_type = message_part.get_content_type()
            attachment.size = len(file_data)
            attachment.name = None
            attachment.create_date = None
            attachment.mod_date = None
            attachment.read_date = None

            for param in dispositions[1:]:
                name,value = param.split("=")
                name = name.lower()

                if name == "filename":
                    attachment.name = value
                elif name == "create-date":
                    attachment.create_date = value  #TODO: datetime
                elif name == "modification-date":
                    attachment.mod_date = value #TODO: datetime
                elif name == "read-date":
                    attachment.read_date = value #TODO: datetime
            return attachment

    return None

def parse(content):
    p = EmailParser()
    msgobj = p.parse(content)
    if msgobj['Subject'] is not None:
        decodefrag = decode_header(msgobj['Subject'])
        subj_fragments = []
        for s , enc in decodefrag:
            if enc:
                try:
                  s = unicode(s , enc).encode('utf8','replace')
                except:
                  pass
            subj_fragments.append(s)
        subject = ''.join(subj_fragments)
    else:
        subject = None

    attachments = []
    body = None
    html = None
    for part in msgobj.walk():
        attachment = parse_attachment(part)
        if attachment:
            attachments.append(attachment)
        elif part.get_content_type() == "text/plain":
            if body is None:
                body = ""
            try:
              body += unicode(
                part.get_payload(decode=True),
                part.get_content_charset(), 'replace').encode('utf8','replace')
            except:
              pass
        elif part.get_content_type() == "text/html":
            if html is None:
                html = ""
            html += unicode(
                part.get_payload(decode=True),
                part.get_content_charset(),
                'replace'
            ).encode('utf8','replace')
    return {
        'subject' : subject,
        'body' : body,
        'html' : html,
        'from' : parseaddr(msgobj.get('From'))[1], 
        'to' : parseaddr(msgobj.get('To'))[1], 
        'attachments': attachments,
    }




for file in filelist:
  print file
  with open(file, 'r') as f:
    data = f.read()
  msg = email.message_from_string(data)
  final_urls = get_urls_list(msg)
'''
lazy coding here.  This path needs to jibe with the global defined at the beginning, and in runvt.py

I need to fix this.
'''
  g = open('/home/foo/malware/processed/urls', 'a')
  for i in final_urls['http']:
    g.write(i + '\n')
  for i in final_urls['https']:
    g.write(i + '\n')
  g.close()
  a = parse(open(file,'r'))
  if a['attachments']:
    #print a['from']
    #print a['to']
    #print a['subject']
    att = a['attachments']
    acount = 1
    for item in att:
      hash = hashlib.sha256(item.getvalue()).hexdigest()
      #print hash
      fn = PAYLOADDIR + '/' + hash + '.attachment' + str(acount)
      with open(fn,'w') as fd:
        item.seek(0)
        shutil.copyfileobj(item, fd)
      acount += 1
    fn = PAYLOADDIR + '/' + hash + '.eml'
    f = open(fn, 'w')
    f.write(str(a))
    f.close()
  os.remove(file)
