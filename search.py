import pprint
import urllib.request
import requests
import http.client
import svgwrite
import json
import time
from googleapiclient.discovery import build


def main():
    # Build a service object for interacting with the API. Visit
    # the Google APIs Console <http://code.google.com/apis/console>
    # to get an API key for your own application.
    service = build("customsearch", "v1",
                    developerKey="AIzaSyAUR--KI1iW_Ow-PumDDA4rlMrIH8bDLyw")
    res = service.cse().list(
        q='salary slip format in excel with formula free downloads',
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
    return loads.get('scans')


if __name__ == '__main__':
    results = main()
    http.client.HTTPConnection.debuglevel = 1
    hdr = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11',
           'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
           'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
           'Accept-Encoding': 'none',
           'Accept-Language': 'en-US,en;q=0.8',
           'Connection': 'keep-alive'}
    counter = 0
    for result in results:
        response = requests.get(result['link'])
        dwg = svgwrite.Drawing(
            "test" + str(counter) + ".svg", profile='tiny')
        circle_radius = 250
        circle_lx = 0
        circle_ly = 0
        text_x = 0
        text_y = 0
        line_x_start = 250
        line_x_end = 650
        line_y_start = 0
        line_y_end = 0
        if response.history:
            for redirect in response.history:
                dwg.add(dwg.circle((circle_lx, circle_ly),
                        r=circle_radius, stroke='blue', fill='white'))
                dwg.add(dwg.text(redirect, insert=(text_x, text_y),
                                          text_anchor="middle", fill='red', font_size="10"))
                if redirect == response.history[-1]:
                    line_x_start = line_x_end = circle_radius + \
                        circle_radius + (line_x_end - line_x_start)
                    line_y_start = circle_lx + circle_radius
                    line_y_end = line_y_start + 400
                    circle_lx = circle_radius + circle_radius + \
                        (line_x_end - line_x_start)
                else:
                    line_x_start = circle_lx + circle_radius
                    line_x_end = line_x_start + 400
                dwg.add(dwg.line((line_x_start, line_y_start), (line_x_end, line_y_end), stroke=svgwrite.rgb(10, 10, 16, '%')))
        else:
            dwg.add(dwg.circle((circle_lx, circle_ly),
                    r=circle_radius, stroke='blue', fill='white'))
            dwg.add(dwg.text(result['link'], insert=(text_x, text_y),
                                      text_anchor="middle", fill='red', font_size="10"))
        request=urllib.request.Request(result['link'], headers=hdr)
        opener=urllib.request.build_opener()
        f=opener.open(request)
        vtotal=virusTotal(f.url)
        if vtotal:
            rect_sx=400
            rect_sy=1030
            rect_lx=line_y_end - (rect_sx / 2)
            rect_ly=line_y_end
            dwg.add(dwg.rect((rect_lx, rect_ly),
                             (rect_sx, rect_sy), fill='grey'))
            scan_text_start_x=900
            scan_text_start_y=680
            for scan in vtotal.items():
                scan_name=scan[0]
                secondary_items=list(scan[1].items())
                scan_detected=secondary_items[0][1]
                scan_result=secondary_items[1][1]
                if scan_detected:
                    dwg.add(dwg.text(scan_name + " - True - " + scan_result, insert=(
                        scan_text_start_x, scan_text_start_y), text_anchor="middle", fill='red'))
                else:
                    dwg.add(dwg.text(scan_name + " - False - " + scan_result, insert=(
                        scan_text_start_x, scan_text_start_y), text_anchor="middle", fill='green'))
                scan_text_start_y += 15
        counter += 1
        dwg.save()
        f.close()
        if counter % 4 == 0:
            time.sleep(62)
