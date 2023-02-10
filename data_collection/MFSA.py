from HEADER import *
from itertools import chain

def extract_ids(txt):
    list_of_ids = []
    f_list_of_ids = []
    if ('https://bugzilla.mozilla.org/buglist.cgi?bug_id=' in txt) & ('%2C' in txt):
        list_of_ids = txt.split('https://bugzilla.mozilla.org/buglist.cgi?bug_id=')[1].split('%2C')
        for el in list_of_ids:
            if '\n' in el:
                f_list_of_ids.append(el.replace('\n', ''))
            else:
                f_list_of_ids.append(el)
        return f_list_of_ids
    elif ('https://bugzilla.mozilla.org/buglist.cgi?bug_id=' in txt):
        list_of_ids = txt.split('https://bugzilla.mozilla.org/buglist.cgi?bug_id=')[1].split('%')
        list_of_ids = list_of_ids[0].split(',')
        for el in list_of_ids:
            if '\n' in el:
                f_list_of_ids.append(el.replace('\n', ''))
            else:
                f_list_of_ids.append(el)
        return f_list_of_ids

def reporters_MFSA(url):
    issues_url_all=[]
    releases_all=[]
    reporters = []
    final = []
    releases=""
#     time.sleep(0.5 +  numpy.random.uniform(0,1))
    r=requests.get(url)
    data = r.text
    main_url_each_release = BeautifulSoup(data,'lxml')
    time_released=main_url_each_release.find('dl',class_='summary')
    if time_released.findAll('dt')[0].text=='Announced':
          releases=time_released.findAll('dd')[0].text

    if time_released.findAll('dt')[1].text=='Reporter':
        bugs=main_url_each_release.findAll('ul')
        for each in bugs:
            isvalid=each.select('.mzp-l-main a')
            if isvalid:
                for el in isvalid:
                    final.append(el)
        urls_in_page=[]
        for ele in final:
            urls_in_page.append(ele['href'])
        urls_in_page=[x for x in urls_in_page if ('#CVE' not in x) & ('http://cve.mitre.org' not in x)]
        for i in range(len(urls_in_page)):
            reporters.append(time_released.findAll('dd')[1].text)
    else:
        all_reporters=main_url_each_release.findAll('section', class_ = 'cve')
        for each_issue in all_reporters:
            reporters_all=each_issue.find('dl',class_='summary')
            if reporters_all.findAll('dt')[0].text=='Reporter':
                number_issues_ref=len(each_issue.find('ul'))-2
                if (number_issues_ref>=2):
                    for x in range(number_issues_ref):
                         reporters.append(reporters_all.findAll('dd')[0].text)
                else:
                    reporters.append(reporters_all.findAll('dd')[0].text)
    #each page has links of issues or references to a page with links of issues
    #some pages have different layouts
    if main_url_each_release.select('.cve a'):
        bugs=main_url_each_release.findAll('ul')
        for each in bugs:
            isvalid=each.select('.cve a')
            if isvalid:
                for e in isvalid:
                        issues_url_all.append(e['href'])
        issues_url_all=[x for x in issues_url_all if ('#CVE' not in x) & ('http://cve.mitre.org' not in x)]
        for x in range(len(issues_url_all)):
                    releases_all.append(releases)
    else:
        bugs=main_url_each_release.findAll('ul')
        for each in bugs:
            valids=each.select('.mzp-l-main a')
            if valids:
                for el in valids:
                        issues_url_all.append(el['href'])
        issues_url_all=[x for x in issues_url_all if ('#CVE' not in x) & ('http://cve.mitre.org' not in x)]
        for x in range(len(issues_url_all)):
                        releases_all.append(releases)
    df=pd.DataFrame(issues_url_all,columns=['Url'])
    df['Releases'] = releases_all
    df['BugID']=df['url'].str.extract('(\d+)')
    df['Reporters']=reporters
    df=df.dropna()
    return df
