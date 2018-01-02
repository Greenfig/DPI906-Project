import pprint
import urllib.request
import requests
import http.client
import svgwrite
import json
from googleapiclient.discovery import build


def main():
    # Build a service object for interacting with the API. Visit
    # the Google APIs Console <http://code.google.com/apis/console>
    # to get an API key for your own application.
    service = build("customsearch", "v1",
                    developerKey="AIzaSyAwKpKag5OLGW8NSCl2FLgN0LUK7qLoelM")
    res = service.cse().list(
        q='nordea sweden bank account number',
        cx='000891665926514897966:jvvhkj-zmoe',
    ).execute()
    return res['items']


def virusTotal(url):
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
    return loads['scans']


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
        title = result['title']
        link = result['link']
        dis = result['snippet']
        request = urllib.request.Request(link, headers=hdr)
        opener = urllib.request.build_opener()
        f = opener.open(request)
        print("TITLE : " + title)
        print("LINK : " + link)
        print("SNIPPET : " + dis)
        print("LANDING PAGE : " + f.url)
        print("=================================================")
        vtotal = virusTotal(f.url)
        dwg = svgwrite.Drawing("test.svg", profile='tiny')
        dwg.add(dwg.circle((0, 0), r=250, fill='blue'))
        dwg.add(dwg.text(link, insert=(0, 0),
                text_anchor="middle", fill='red', font_size="10"))
        dwg.add(dwg.line((250, 0), (650, 0), stroke=svgwrite.rgb(10, 10, 16, '%')))
        dwg.add(dwg.circle((250 + 400 + 250, 0), r=250, fill='blue'))
        dwg.add(dwg.text(f.url, insert=(250 + 400 + 250, 0),
                text_anchor="middle", fill='red', font_size="10"))
        dwg.add(dwg.line((250 + 400 + 250, 250), (250 + 400 + 250, 650),
                         stroke=svgwrite.rgb(10, 10, 16, '%')))
        rect_sx = 400
        rect_sy = 1030
        dwg.add(dwg.rect(((250 + 400 + 250) - (rect_sx / 2), 650),
                (rect_sx, rect_sy), fill='grey'))
        scan_text_start_x = 900
        scan_text_start_y = 680
        for scan in vtotal.items():
          scan_name = scan[0]
          secondary_items = list(scan[1].items())
          scan_detected = secondary_items[0][1]
          scan_result = secondary_items[1][1]
          if scan_detected:
            dwg.add(dwg.text(scan_name+" - True - "+scan_result, insert=(scan_text_start_x, scan_text_start_y), text_anchor="middle", fill='red'))
          else:
            dwg.add(dwg.text(scan_name+" - False - "+scan_result, insert=(scan_text_start_x, scan_text_start_y), text_anchor="middle", fill='green'))
          scan_text_start_y += 15
        dwg.save()
        f.close()
        break
