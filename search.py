import pprint
from urllib.request import urlopen, quote, urljoin, urlretrieve
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


def main():
    # Build a service object for interacting with the API. Visit
    # the Google APIs Console <http://code.google.com/apis/console>
    # to get an API key for your own application.
    service = build("customsearch", "v1",
                    developerKey="AIzaSyBj7XXzShIGQb1SBi2aDkNiyn_Z7VFPM1A")
    res = service.cse().list(
        q='salary slip format in excel with formula free downloads',
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
    hash_md5 = hashlib.md5()
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    hashcode = hash_md5.hexdigest()
    headers = {
        "Accept-Encoding": "gzip, deflate",
        "User-Agent": "gzip,  My Python requests library example client or username"
    }
    params = {'apikey': '83af3fd41034cf9546ef08684d1f3d89c603d30d6af8176e842db2042e8807ff',
              'resource': hashcode}
    files = {'file': (filename, open(filename, 'rb'))}
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
                            params=params, headers=headers)
    json_response = response.json()
    dumps = json.dumps(json_response)
    loads = json.loads(dumps)
    time.sleep(16)
    return loads.get('scans')


def get_hops(url):
    redirect_re = re.compile('<meta[^>]*?url=(.*?)["\']', re.IGNORECASE)
    hops = []
    old = url
    hops.insert(0, url)
    while url:
        decoded = urlopen(url).read().decode('utf-8')
        match = redirect_re.search(decoded)
        if match is not None:
            url = match.group(1)
            hops.insert(0, url)
            old = url
        else:
            url = None
    return list(reversed(hops))


def getDownloadList(url):
    c = 0
    u = urlopen(url)
    try:
        html = u.read().decode('utf-8')
    finally:
        u.close()
    soup = BeautifulSoup(html)
    mylist = []
    for link in soup.find_all('a', href=True):
        l = link.get('href')
        regex = re.compile('(\/[a-zA-z0-9-_]+\.[a-zA-Z]+)$')
        if regex.search(l):
            regex = re.compile('(\/[a-zA-z0-9-_]+\.[a-zA-Z]+)$')
            filename = regex.search(l).group(1).replace("/", "")
            urlretrieve(l, filename)
            mylist.insert(c, filename)
            c += 1
    return mylist


if __name__ == '__main__':
    results = main()
    http.client.HTTPConnection.debuglevel = 1
    hdr = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11',
           'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
           'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
           'Accept-Encoding': 'none',
           'Accept-Language': 'en-US,en;q=0.8',
           'Connection': 'keep-alive'}
    for result in results:
        #response = get_hops("https://s3.amazonaws.com/aws-website-dpiproject-bwm6w/index.html")
        response = get_hops(result['link'])
        #response = get_hops("http://gynvael.coldwind.pl/")
        svgfile_regex = re.compile('(\/\/[a-zA-z0-9-_]+\.[a-zA-Z]+)')
        svgfile_name = svgfile_regex.search(result['link']).group(
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
        line_y_start = line_x_start + circle_radius
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
                    if not first:
                        first = scan
                    scan_name = scan[0]
                    secondary_items = list(scan[1].items())
                    scan_detected = secondary_items[0][1]
                    scan_result = secondary_items[1][1]
                    if scan_detected:
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
                if vtotal:
                    if len(vtotal.keys()) > 0:
                        for scan in vtotal.items():
                            scan_name = scan[0]
                            secondary_items = list(scan[1].items())
                            scan_detected = secondary_items[0][1]
                            scan_result = secondary_items[1][1]
                            if scan_detected:
                                isMalicious = True
                                dwg.add(dwg.text(scan_name + " - True - " + scan_result, insert=(
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
