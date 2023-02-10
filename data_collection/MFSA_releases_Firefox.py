from data_collection.info_extraction import *
from data_collection.URLS import *
from HEADER import *
from data_collection.MFSA import extract_ids



firefox_MFSA_versions = pd.DataFrame()
versions_urls = []
versions = []
urls = []

for each_link in tqdm.tqdm(MFSA_FIREFOX):
    time.sleep(1.0 + numpy.random.uniform(0, 1))
    r = requests.get(each_link)
    data = r.text
    d_stables = BeautifulSoup(data,'lxml')
    versions_urls.append(d_stables.select('.level-item a'))

versions_urls = list(chain.from_iterable(versions_urls))
for each_url in versions_urls:
    urls.append(each_url['href'])
    versions.append(each_url['data'])

firefox_MFSA_versions['Versions'] = versions
firefox_MFSA_versions['Urls'] = urls
firefox_MFSA_versions['Urls'] = "https://www.mozilla.org" + firefox_MFSA_versions['Urls']

list_urls = firefox_MFSA_versions['Urls'].tolist()

issues_url_all=[]
releases_all=[]
for url in tqdm.tqdm(list_urls):
    releases=""
    time.sleep(1.5 +  numpy.random.uniform(0,1))
    r=requests.get(url)
    data = r.text
    main_url_each_release = BeautifulSoup(data,'lxml')
    time_released=main_url_each_release.find('dl',class_='summary')
    if time_released.findAll('dt')[0].text=='Announced':
          releases=time_released.findAll('dd')[0].text
    #each page has links of issues or reference to a page with inks of issues
    #some pages have different layout
    if main_url_each_release.select('.cve a'):
        urls_issues=main_url_each_release.select('.cve a')
        for a in urls_issues:
            issues_url_all.append(a['href'])
            releases_all.append(releases)
    else:
        urls_issues=main_url_each_release.select('.mzp-l-main a')
        for a in urls_issues:
            issues_url_all.append(a['href'])
            releases_all.append(releases)

df=pd.DataFrame(issues_url_all,columns=['url'])
df['releases'] = releases_all
df = df[~df['url'].astype(str).str.startswith('#CVE')]
df=df[df['url'].str.startswith('https://bugzilla')]
df['BugID']=df['url'].str.extract('(\d+)')


df['extras']=df['Url'].apply(lambda s: extract_ids(s))
df[~df['extras'].isna()]
df=df.explode('extras')
df=df.reset_index()
df.loc[(~df['extras'].isna()), 'BugID_2'] = df['extras']
df.loc[df['extras'].isna(),'BugID_2'] = df['BugID']
del df['BugID']
# del df_releases['extras']
df=df.rename(columns = {'BugID_2':'BugID'})
df=df[['BugID', 'releases']]
df=df[df['BugID']!=""]
df['BugID']=df['BugID'].apply('int64')
df['IsStable']=1

# df.to_csv('../data/Firefox/stable_releases_Firefox.csv', index = False)
