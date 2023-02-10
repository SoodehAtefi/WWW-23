from HEADER import *

def extract_url(x):
    return re.search("(?P<url>https?://[^\s]+)", x).group("url")


def collect_links(url):
    lis = []
    inaccessibles = ""
    layouts_diff = ""
    if (requests.get(url)):
        #          print('ok')
        r = requests.get(url)
        #         print(r.text)
        data = r.text
        soup = BeautifulSoup(data, 'xml')
        if (soup.find_all('ul', class_='DiffTree')):
            for ul in soup.find_all('ul', class_='DiffTree'):
                for li in ul.find_all('li'):
                    a = li.find('a')
                    lis.append(a['href'])
        else:
            print('different layouts')
            layouts_diff = url
            for td in soup.find_all('td'):
                link = td.parent.select_one("td > a")
                if link:
                    lis.append(link.text)
    #                     time.sleep(1.0+ np.random.uniform(0, 1))
    else:
        #         print('error')
        inaccessibles = url
        time.sleep(1.0 + np.random.uniform(0, 1))
    return inaccessibles, layouts_diff, lis
issues=pd.read_csv('../data/Chromium/ISSUES.csv',low_memory=False)
org_issues=issues[(issues['IsValid']==1)& (issues['LocalID']==issues['PseudoID'])]
valid_orgs=org_issues.LocalID.tolist()
valid_orgs=[str(x) for x in valid_orgs]
comments=pd.read_csv('../data/Chromium/COMMENTS_Chromium.csv')
#Search for the comments that contain git sources
valid_comments=comments[(comments['Content'].str.contains('The following revision refers to this bug:')) & (~comments['Content'].isna()) & (comments['LocalID'].isin(valid_orgs))]
valid_comments['Urls']=valid_comments['Content'].apply(lambda x:extract_url(x)).tolist()

aggregated_cols =valid_comments.groupby('LocalID')['Urls'].agg(','.join).reset_index()
dic_all=dict(zip(aggregated_cols.LocalID,aggregated_cols.Urls))
final_dic ={}
for key,value in dic_all.items():
    final_dic[key]=value.split(',')
ids = list(final_dic.keys())
print('Number of issues that have revision links: ',len(ids))

dict_results = {}
urls_inaccessibles={}
different_layouts={}
for key,value in tqdm.tqdm(final_dic.items()):
    list_of_urls = []
    urlsinaccessibles=[]
    differentlayouts=[]
    for each_url in value:
        inaccessible,difflayouts,temp=collect_links(each_url)
        list_of_urls.append(list(set(temp)))
        urlsinaccessibles.append(inaccessible)
        differentlayouts.append(difflayouts)
    dict_results[key]=list_of_urls
    urls_inaccessibles[key]=urlsinaccessibles
    different_layouts[key]=differentlayouts

# with open('../data/Chromium/chrom_lang_suffix.pickle', 'wb') as handle:
#     pickle.dump(dict_results, handle)

#Cleaning Languages to be able to merge to the main data

langues_per_issue= {}
for key,value in dict_results.items():
        new_li = [item for items in value for item in items]
        list_of_langs =[x.split('.')[-1] for x in new_li if '.' in x]
        list_of_langs=list(set(list_of_langs))
        langues_per_issue[key]=list_of_langs
#Valid languages are cleaned manually
langs=['m4', 'js','xml','cc','css','cpp','py','xhtml','html','c','php','java','xsl','htm','pl','asm','jsm','cxx','pm','el','sjs','scss']
new_lang_dict={}
for key,value in langues_per_issue.items():
    temp =[]
    for x in value:
        if x in langs:
            temp.append(x)
    new_lang_dict[key]=temp
merge_same_langs = {}
for key, value in new_lang_dict.items():
    temp = []
    for ele in value:
        if ele == 'cxx' or ele == 'cc':
            temp.append('cpp')
        elif ele == 'sjs' or ele == 'jsm':
            temp.append('js')
        elif ele == 'htm' or ele == 'xhtml':
            temp.append('html')
        elif ele == 'sass':
            temp.append('scss')
        elif ele == 'pm':
            temp.append('pl')
        else:
            temp.append(ele)
    temp = list(set(temp))
    merge_same_langs[key] = temp

df=pd.DataFrame((k, x) for k,v in merge_same_langs.items() for x in v)
df.groupby(1)[0].nunique().reset_index(name = 'count')
df=df.rename(columns = {0:'LocalID', 1: 'Language'})
df.loc[(df['Language']=='cpp'), 'Language']='C++'
df.loc[(df['Language']=='js'), 'Language']='JS'
df.loc[(df['Language']=='html'), 'Language']='HTML'
df.loc[(df['Language']=='c'), 'Language']='C'
df.loc[(df['Language']=='py'), 'Language']='Python'
df.loc[(df['Language']=='xml'), 'Language']='XML'
df.loc[(df['Language']=='java'), 'Language']='JAVA'
df.loc[(df['Language']=='css'), 'Language']='CSS'
df.loc[(df['Language']=='m4'), 'Language']='M4'
df.loc[(df['Language']=='php'), 'Language']='PHP'

df_final = (df.groupby(['LocalID']).agg({'Language': lambda x: x.tolist()}).reset_index())


# df_final.to_csv('../data/Chromium/Languages_Chrom.csv', index =False)