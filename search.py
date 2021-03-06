import pprint
from urllib.request import urlopen, quote, urljoin, urlretrieve, Request
from urllib.error import HTTPError
import requests
import http.client
import svgwrite
import json
import time
from urllib.parse import urljoin
from googleapiclient.discovery import build
from bs4 import BeautifulSoup
import re
import hashlib
import os


def main():
    # Build a service object for interacting with the API. Visit
    # the Google APIs Console <http://code.google.com/apis/console>
    # to get an API key for your own application.
    service = build("customsearch", "v1",
                    developerKey="AIzaSyAocvBVxj896xsymEkdk_vjXucwpJAcGgE")
    res = service.cse().list(
        q='salary slip format in excel with formula free download',
        cx='000891665926514897966:jvvhkj-zmoe',
    ).execute()
    return res['items']

# Acts as a global variable to control virustotal.com query limit (4 per 60s)


def virusTotalUrl(url):
    headers = {
        "Accept-Encoding": "gzip, deflate",
        "User-Agent": "gzip, vtotal"
    }
    params = {
        'apikey': '83af3fd41034cf9546ef08684d1f3d89c603d30d6af8176e842db2042e8807ff', 'resource': url}
    response = requests.post(
        'https://www.virustotal.com/vtapi/v2/url/report', params=params, headers=headers)
    json_response = response.json()
    dumps = json.dumps(json_response)
    loads = json.loads(dumps)
    time.sleep(16)
    return loads.get('scans')


def virusTotalFile(filename):
    hash_sha2 = hashlib.sha256()
    hash_md5 = hashlib.md5()
    hash_sha1 = hashlib.sha1()
    hashcode = []
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha2.update(chunk)
            hash_md5.update(chunk)
            hash_sha1.update(chunk)
    hashcode.insert(0,hash_sha2.hexdigest())
    hashcode.insert(0, hash_md5.hexdigest())
    hashcode.insert(0, hash_sha1.hexdigest())
    os.remove(filename)

    headers = {
        "Accept-Encoding": "gzip, deflate",
        "User-Agent": "gzip,  My Python requests library example client or username"
    }
    for h in hashcode:
        params = {'apikey': '83af3fd41034cf9546ef08684d1f3d89c603d30d6af8176e842db2042e8807ff',
                'resource': h}
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
                                params=params, headers=headers)
        json_response = response.json()
        dumps = json.dumps(json_response)
        loads = json.loads(dumps)
        time.sleep(16)
        if loads.get('response_code') == 1:
            return loads.get('scans')
    return loads.get('scans')

def get_hops(url):
    redirect_re = re.compile('<meta[^>]*?url=(.*?)["\']', re.IGNORECASE)
    hops = []
    old = url
    hdr = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11',
       'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
       'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
       'Accept-Encoding': 'none',
       'Accept-Language': 'en-US,en;q=0.8',
       'Connection': 'keep-alive'}
    hops.insert(0, url)
    
    while url:
        try:
            reqst = Request(url, headers=hdr)
            decoded = urlopen(reqst).read().decode('utf-8')
        except (HTTPError, ValueError):
            return None
        match = redirect_re.search(decoded)
        if match is not None:
            url = match.group(1)
            hops.insert(0, url)
            old = url
        else:
            url = None
    return list(reversed(hops))


def getDownloadList(url):
    hdr = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
    'Accept-Encoding': 'none',
    'Accept-Language': 'en-US,en;q=0.8',
    'Connection': 'keep-alive'}
    reqst = Request(url, headers=hdr)
    u = urlopen(reqst)
    try:
        html = u.read().decode('utf-8')
    finally:
        u.close()
    soup = BeautifulSoup(html, "html.parser")
    mylist = []
    for link in soup.find_all('a', href=True):
        l = link.get('href')
        filename = l.split('/')[-1]
        if filename:
            if "www." not in filename:
                if ".html" not in filename:
                    if ".php" not in filename:
                        if ".aspx" not in filename:
                            if ".htm" not in filename:
                                if "#" not in filename:
                                    try:
                                        if "http" not in l:
                                            #remove forward slash from the url
                                            if "/" in url[-1]:
                                                url = url[:-1]
                                            l = url + "/" + filename
                                        urlretrieve(l, filename)                         
                                        mylist.insert(0, filename)
                                    except ValueError:
                                        print ("download failed")
    return mylist


if __name__ == '__main__':
    results = { 'link':'link' }
    #results = main()
    #results['link'] = "http://eagleepicsocks.com/2d/"
    #results['link'] = "http://umunna.info"
    #results['link'] = "http://peceducacion.com"
    #results['link'] = "http://critical-virus.xyz/new"
    results['link'] = "https://s3.amazonaws.com/aws-website-dpiproject-bwm6w/index.html"
    #results['link'] = "http://smartnewtab.com/"
    #results['link'] = "https://exceldatapro.com/download-salary-sheet-template/"
    for result in results:
        #response = get_hops(result['link'])
        response = get_hops(results['link'])
        if not response:
            continue
        svgfile_regex = re.compile('(\/\/[a-zA-z0-9-_]+\.[a-zA-Z]+)')
        svgfile_name = svgfile_regex.search(response[0]).group(
            1).replace("//", "").replace(".com", "")
        dwg = svgwrite.Drawing(
            svgfile_name + ".svg", profile='tiny')
        circle_radius = 250
        circle_lx = 0
        circle_ly = 0
        text_x = 0
        text_y = 0
        line_x_start = 250
        line_x_end = 650
        line_y_start = 0
        line_y_end = 0
        # Follow redirects
        if response:
            for redirect in response:
                dwg.add(dwg.circle((circle_lx, circle_ly),
                                   r=circle_radius, stroke='blue', fill='white'))
                dwg.add(dwg.text(redirect, insert=(text_x, text_y),
                                 text_anchor="middle", fill='red', font_size="10"))
                # if there are more urls to add calculate the new circle and print the line horizontally
                if redirect != response[-1]:
                    # calculate the line position
                    line_x_start = circle_lx + circle_radius
                    line_x_end = line_x_start + 400
                    dwg.add(dwg.line((line_x_start, line_y_start), (line_x_end,
                                                                    line_y_end), stroke=svgwrite.rgb(10, 10, 16, '%')))
                    # calculate new circle coordinates
                    circle_lx = text_x = line_x_end + circle_radius
            landingpage = response[-1]
        else:
            dwg.add(dwg.circle((circle_lx, circle_ly),
                               r=circle_radius, stroke='blue', fill='white'))
            dwg.add(dwg.text(result['link'], insert=(text_x, text_y),
                             text_anchor="middle", fill='red', font_size="10"))
            landingpage = response
        # Query virus total on url
        vtotal = virusTotalUrl(landingpage)
        line_x_start = line_x_end = circle_lx
        line_y_start = circle_radius
        line_y_end = line_y_start + 400
        dwg.add(dwg.line((line_x_start, line_y_start), (line_x_end,
                                                        line_y_end), stroke=svgwrite.rgb(10, 10, 16, '%')))
        rect_sx = 400
        rect_sy = 30
        rect_lx = line_x_end - (rect_sx / 2)
        rect_ly = line_y_end
        rectangle = dwg.add(dwg.rect((rect_lx, rect_ly),
                                     (rect_sx, rect_sy), fill='white', stroke="grey"))
        scan_text_start_x = rect_lx + 200
        scan_text_start_y = rect_ly + 20
        isMalicious = False
        if vtotal:
            if len(vtotal.keys()) > 0:
                first = None
                for scan in vtotal.items():
                    scan_name = scan[0]
                    secondary_items = list(scan[1].items())
                    scan_detected = secondary_items[0][1]
                    scan_result = secondary_items[1][1]
                    if scan_detected:
                        if not first:
                            first = scan
                        if scan != first:
                            line_y_start = line_y_end + rect_sy
                            line_y_end = line_y_start + 80
                            dwg.add(dwg.line((line_x_start, line_y_start), (line_x_end,
                                                                            line_y_end), stroke=svgwrite.rgb(10, 10, 16, '%')))
                            rect_ly = line_y_end
                            rectangle = dwg.add(dwg.rect((rect_lx, rect_ly),
                                                         (rect_sx, rect_sy), fill='white', stroke="grey"))
                            scan_text_start_x = rect_lx + 200
                            scan_text_start_y = rect_ly + 20
                        isMalicious = True
                        dwg.add(dwg.text(scan_name + " - True - " + scan_result, insert=(
                            scan_text_start_x, scan_text_start_y), text_anchor="middle", fill='red'))
                        scan_text_start_y += 15
            if not isMalicious:
                dwg.add(dwg.text("NO MALICIOUS CONTENT FOUND", insert=(
                    scan_text_start_x, scan_text_start_y), text_anchor="middle", fill='green'))
        else:
            dwg.add(dwg.text("NO SCAN AVAILABLE", insert=(
                scan_text_start_x, scan_text_start_y), text_anchor="middle", fill='green'))
        # Get list of downloadable items

        downloadlist = getDownloadList(landingpage)
        if len(downloadlist) > 0:
            line_x_start = circle_lx + circle_radius
            line_x_end = line_x_start + 400
            line_y_start = 0
            line_y_end = 0
            dwg.add(dwg.line((line_x_start, line_y_start), (line_x_end,
                                                            line_y_end), stroke=svgwrite.rgb(10, 10, 16, '%')))
            rect_lx = line_x_end
            rect_sy += 50
            rect_ly = 0
            regex = re.compile('(\/[a-zA-z0-9-_]+\.[a-zA-Z]+)$')
            for filename in downloadlist:
                rect_ly = line_y_end
                dwg.add(dwg.rect((rect_lx, rect_ly),
                                 (rect_sx, rect_sy), fill='white', stroke="orange"))
                scan_text_start_x = rect_lx + 200
                scan_text_start_y = rect_ly + 20
                dwg.add(dwg.text(filename, insert=(
                        scan_text_start_x, scan_text_start_y), text_anchor="middle", fill='green'))
                scan_text_start_y += 15
                vtotal = virusTotalFile(filename)
                isMalicious = False
                if vtotal:
                    if len(vtotal.keys()) > 0:
                        for scan in vtotal.items():
                            scan_name = scan[0]
                            secondary_items = list(scan[1].items())
                            scan_detected = secondary_items[0][1]
                            if scan_detected:
                                isMalicious = True
                                dwg.add(dwg.text(scan_name + " - True ", insert=(
                                    scan_text_start_x, scan_text_start_y), text_anchor="middle", fill='red'))
                                scan_text_start_y += 15
                                rect_sy += 20
                    if not isMalicious:
                        scan_text_start_y += 15
                        dwg.add(dwg.text("NO MALICIOUS CONTENT FOUND", insert=(
                            scan_text_start_x, scan_text_start_y), text_anchor="middle", fill='green'))
                else:
                    scan_text_start_y += 15
                    dwg.add(dwg.text("NO SCAN AVAILABLE", insert=(
                        scan_text_start_x, scan_text_start_y), text_anchor="middle", fill='green'))
                if filename != downloadlist[-1]:
                    line_x_start = rect_lx + (rect_sx / 2)
                    line_x_end = line_x_start
                    line_y_start = rect_ly + rect_sy
                    line_y_end = line_y_start + 80
                    dwg.add(dwg.line((line_x_start, line_y_start), (line_x_end,
                                                                    line_y_end), stroke=svgwrite.rgb(10, 10, 16, '%')))
        dwg.save()
