from HEADER import *


def get_comment(urls):
    comments=pd.DataFrame()
    list_comments=[]
    list_urls = []
    for url in tqdm.tqdm(urls):
        result=[]
        list_urls.append(url)
        time.sleep( 1.0 +  np.random.uniform(0,1))
        r=requests.get(url)
        data = r.text
        soup = BeautifulSoup(data)
        if soup.find('td', class_ = 'throw_error'):
                print("url is not available",url)
                continue
        else:
            d_comments=soup.findAll('div',attrs={'class':'change-set'})
            for comment in d_comments:
                if comment.find('pre',attrs={"class":"comment-text"}):
                    data=comment.find('pre',attrs={"class":"comment-text"})
                    result.append(data.get_text())
                if comment.find('div',attrs={"class":"comment-text markdown-body"}):
                    data=comment.find('div',attrs={"class":"comment-text markdown-body"})
                    result.append(data.get_text())
            list_to_str = ' '.join([str(elem) for elem in result])
            list_comments.append(list_to_str)
    comments['BugID']=list_urls
    comments['Comments']=list_comments
    return comments


data =pd.read_csv('../data/Firefox/data_to_collect_weakness_langs.csv')
bug_ids=data['BugID'].tolist()
urls_all = []
for x in bug_ids:
    urls_all.append('https://bugzilla.mozilla.org/show_bug.cgi?id='+ str(x))
df_comments=get_comment(urls_all)

df_comments['BugID']=df_comments['BugID'].str.extract('(\d+)')
df_comments['BugID']=df_comments['BugID'].astype('int64')
issue_summary=data[['BugID', 'Summary']]
df_comments=df_comments.merge(issue_summary, on = 'BugID', how = 'left')

df_comments['IsExploited']=(df_comments['Comments'].str.contains('exploited in the wild')) |(df_comments['Comments'].str.contains('exploited security vulnerability'))|(df_comments['Comments'].str.contains('exploit in the wild')) |(df_comments['Comments'].str.contains('exploits are in the wild'))|(df_comments['Comments'].str.contains('exploitable in the wild'))|(df_comments['Comments'].str.contains('exploitability in the wild'))|(df_comments['Comments'].str.contains('exploiting in wild'))|(df_comments['Comments'].str.contains('used in wild'))|(df_comments['Comments'].str.contains('used in the wild'))|(df_comments['Comments'].str.contains('used in a wild'))|(df_comments['Comments'].str.contains('out in the wild')) |(df_comments['Comments'].str.contains('occurring in the wild')) |(df_comments['Comments'].str.contains('occurring in-the-wild')) |(df_comments['Comments'].str.contains('occurs in the wild')) |(df_comments['Comments'].str.contains('happening in-the-wild')) |(df_comments['Comments'].str.contains('happening in the wild')) |(df_comments['Comments'].str.contains('abused in the wild')) |(df_comments['Comments'].str.contains('present in the wild')) |(df_comments['Comments'].str.contains('observed in the wild')) |(df_comments['Comments'].str.contains('already in the wild')) |(df_comments['Comments'].str.contains('seen in the wild')) |(df_comments['Comments'].str.contains('"in the wild"')) |(df_comments['Comments'].str.contains('in-the-wild')) |(df_comments['Comments'].str.contains('in wild')) |(df_comments['Comments'].str.contains('from the wild')) |(df_comments['Comments'].str.contains('zero day')) |(df_comments['Comments'].str.contains('zero-day')) | (df_comments['Summary'].str.contains('zero day')) | (df_comments['Summary'].str.contains('zero-day'))

df_comments['IsnotExploited']=(df_comments['Comments'].str.contains('happens in the wild'))| (df_comments['Comments'].str.contains('show up in the wild')) | (df_comments['Comments'].str.contains('test in the wild'))| (df_comments['Comments'].str.contains('enabled in the wild')) | (df_comments['Comments'].str.contains('crashes in the wild')) | (df_comments['Comments'].str.contains('reachable up in the wild')) | (df_comments['Comments'].str.contains('triggered in the wild')) | (df_comments['Comments'].str.contains('triggerable in the wild')) | (df_comments['Comments'].str.contains('manifest in the wild'))

df_exploited=df_comments[(df_comments['IsExploited']==True) & (df_comments['IsnotExploited']==False)]
df_exploited=df_exploited[['BugID','IsExploited']]


# df_comments.to_pickle("../data/Firefox/comments_Firefox.pkl")
# df_exploited.to_csv("../data/Firefox/Isexploited_Firefox.csv")
