import sys,os,json

def find_files(d,ext):
    ans=[]
    if os.path.isdir(d):
        for c in os.listdir(d):
            ans+=find_files(d+'/'+c,ext)
    elif os.path.isfile(d) and d.endswith(ext):
        ans+=[d]
    return ans

def dfs(mp,name):
    ans=set()
    if isinstance(mp,dict):
        for field in mp.keys():
            if field  == name:
                ans|=set(mp[field])
            else:
                ans|=dfs(mp[field],name)
    return ans

def preprocess(url,legal=set([':','/','.'])):
    url = url.strip()
    puncs = set(filter(lambda x: not x.isalnum(),url))
    if len(puncs -  legal)>0 or '///' in url:
        return None
    elif not url.startswith('http'):
        url = 'http://'+url
    return url


def process(data_folder,url_file):
    json_files =  find_files(data_folder,'.json')
    collected_urls=set()
    for json_file in json_files:
        with open(json_file,'r') as f:
            data = json.load(f)
        # explore apk file
        collected_urls|=dfs(data,'urls')
    collected_urls = map(lambda x: preprocess(x),collected_urls)
    collected_urls = filter(lambda x:x is not None , collected_urls)
    with open(url_file,'w') as writer:
        writer.write('url\n')
        writer.write('\n'.join(list(collected_urls))+'\n')
if __name__ == '__main__':
    data_folder= '/media/duy/DSSD4/ResearchSpace/sandbox_two/SANER_apps/sep_diff'    
    url_file='apk_urls.csv'
    process(data_folder,url_file)
