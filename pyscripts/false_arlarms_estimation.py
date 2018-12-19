import random,sys,os
random.seed(3223)
def create_folds(apks,n_folds):
    random.shuffle(apks)
    ans=[]
    size=n_folds
    while size>0:
        n = (len(apks)+1)//size
        n = min(n,len(apks))
        ans+=[apks[:n]]
        apks=apks[n:]
        size-=1
    return ans



def parse_permissions(input_folder):
    ans={}
    for f in os.listdir(input_folder):
        if os.path.isfile(input_folder+'/'+f):
            id = f[:f.find('.')]
            f = input_folder+'/'+f
            ################
            apk={}
            with open(f,'r') as reader:
                lines=[l.strip() for l in reader]
                for l in lines:
                    index = l.rfind('>')
                    method = l[:index+1].strip()
                    pstr =  l[index+1:].strip().split()
                    if len(pstr)>0:
                        apk[method]=pstr
                    else:
                        continue
            #################
            ans[id]=apk
    return ans

def compute_false_arlarms(train_apks,test_apks,apk_permissions):
    train = set()
    for apk in train_apks:
        method2permissions = apk_permissions[apk]
        for e in method2permissions.values():
            train|=set(e)
    #############################
    test = set()
    for apk in test_apks:
        method2permissions = apk_permissions[apk]
        for e in method2permissions.values():
            test|=set(e)
    return len(set([e for e in test if e not in train]))>0

def process(apk_pair_file,permission_list_folder,n_folders=10):
    
    with open(apk_pair_file,'r') as reader:
        lines=[l.strip().replace(',',' ').split() for l in reader]
        lines = [list(filter(lambda x:len(x)>0,e)) for e in lines]
        benign_apks={e[0]:e[-1] for e in lines}

    ########################################################

    apk_permissions = parse_permissions(permission_list_folder)

    ########################################################
    print("Number of benign apks:",len(benign_apks))
    folds = create_folds(list(benign_apks.keys()),n_folders)
    #print(benign_apks.keys())
    FAR=0
    for fid in range(len(folds)):
        test_apks = folds[fid]
        ###############################
        train_apks =[]
        for x in range(len(folds)):
            if x!=fid:
                train_apks+=folds[x]
        ###############################
        fold_false_arlarms = compute_false_arlarms(train_apks,test_apks,apk_permissions)
        t=fold_false_arlarms
        FAR+=t
        #print(fid,len(folds[fid]),"FAR:",t)
    print("Total false arlamrs:",FAR)
    FAR = FAR / len(benign_apks)*100.0
    print("FAR:",FAR)


if __name__ == '__main__':
    apk_pair_file='selected_apps.txt'
    permission_list_folder='to_record_methods'
    process(apk_pair_file,permission_list_folder)