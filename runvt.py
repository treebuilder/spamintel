#!/usr/bin/python

import argparse
import requests
import hashlib
import os
import glob
import time
from os import listdir
from os.path import isfile, join

'''
You'll need to adjust the paths to suit your needs, and provide your own VirusTotal API key.
'''
PAYLOADDIR = '/home/DIRECTORYNAME/malware'
PROCESSEDDIR = '/home/DIRECTORYNAME/malware/processed'
APIKEY = 'YOUR_API_KEY'


filelist = []
fl = [f for f in listdir(PAYLOADDIR) if isfile(join(PAYLOADDIR,f))]
for item in fl:
  if 'attachment' in item:
    filelist.append(join(PAYLOADDIR,item))


def checkVT(key, hash):
  hash = hash.strip()
  key = key.strip()
  params = {'apikey': key, 'resource': hash}
  conn = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
  result = conn.json()
  code = int(result.get('response_code'))
  if code == 0:
    #print "%s not found" % hash
    return result, 2
  elif code == 1:
    pos = int(result.get('positives'))
    if pos == 0:
      #print "%s benign" % hash
      return result, 0
    else:
      #print "%s malicious" % hash
      return result, 1
    #print result
  else:
    #print "Search failed"
    return None, 3

def glist(hash):
  return glob.glob(PAYLOADDIR + '/' + hash + '*')

def submitVT(key, fn):
  fn = fn.strip()
  key = key.strip()
  params = {'apikey': key}
  files = {'file': (fn, open(fn, 'rb'))}
  conn = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
  result = conn.json()

def main():
  '''
  iterate through filelist, which is the hash.attachment# filenames.
  split on . and grab the first element
  check that as a hash against VT
  if it's benign, delete it.
  if it's malicious, move it to processed.
  if it's unknown, leave it in place and submit it to VT
  '''

  for item in filelist:
    print item
    hash = item.split('.')[0].split('/')[-1]
    result, rc = checkVT(APIKEY, hash)
    '''
    return codes:
      0 = benign
      1 = malicious
      2 = not found
      3 = search error
    '''
    if rc == 0:
      for f in glist(hash):
        os.remove(f)
    if rc == 1:
      for f in glist(hash):
        os.rename(f, PAYLOADDIR + '/processed/' + f.split('/')[-1])
      # write result to file in processed
      rfile = PAYLOADDIR + '/processed/' + hash + '.result'
      fw = open(rfile, 'w')
      fw.write(str(result))
      fw.close()
    if rc == 2:
      # submit file to VT
      submitVT(APIKEY, item)
    time.sleep(16)



if __name__ == main():
  main()


