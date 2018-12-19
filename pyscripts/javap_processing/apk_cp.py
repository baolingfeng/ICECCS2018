import sys,os,shutil
def process(apk_pair_list,src_apk_dir,dest_apk_dir):
    apk_set=set()
    with open(apk_pair_list,'r') as reader:
        lines=[l.strip().replace(',','').split() for l in reader]
        lines = [list(filter(lambda x:len(x)>0, e)) for e in lines]
        for e in lines:
            apk_set|=set(e)
    #########
    if not os.path.isdir(dest_apk_dir):
        os.makedirs(dest_apk_dir)
    for apk in apk_set:
        print('copying',apk)
        shutil.copyfile(src_apk_dir+'/'+apk+'.apk',dest_apk_dir+'/'+apk+'.apk')

if __name__=='__main__':
    apk_pair_list='/media/duy/DSSD4/ResearchSpace/sandbox_two/SANER_apps/10small_apps.txt'
    src_apk_dir='/media/duy/DUY_HITACHI/piggybacked2'
    dest_apk_dir='/media/duy/DSSD4/ResearchSpace/sandbox_two/SANER_apps/apks'
    process(apk_pair_list,src_apk_dir,dest_apk_dir)
    