import sys,os,json
import random
random.seed(2342423)

def compute_f1(true_negatives,true_positives,false_negatives,false_positives):
    precision  = true_positives/(true_positives+false_positives)
    recall = true_positives/(true_positives+false_negatives)
    f1 = 2.0 *precision*recall /(precision+recall) if precision+recall >0 else 0.0
    precision = round(100.0*precision,2)
    recall = round(100.0*recall,2)
    f1 = round(100.0*f1,2)
    return precision,recall,f1

def create_folds(apks,n_folds):
    apks=list(apks)
    apks.sort()
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

def compute_true_alarms(apk_pairs,data):
    TAR=0
    detected_cases=[]
    undetected_cases=[]
    for (benign,malicious) in apk_pairs:
        diff = data[(benign,malicious)]
        detected=False
        for gui in diff:
            if len(diff)>0:
                detected=True
                break
        if detected:
            TAR+=1
            detected_cases+=[(benign,malicious)]
        else:
            undetected_cases+=[(benign,malicious)]
    true_positives=TAR
    false_negatives=len(apk_pairs)-TAR 
    return 100.0*TAR/len(apk_pairs),true_positives,false_negatives,detected_cases,undetected_cases

def extract_data(apks_list,data):
    ans={}
    for apk in apks_list:
        for head in data[apk]:
            if head not in ans:
                ans[head]=set()
            ans[head]|=set(data[apk][head])
    return ans

def sandbox_simulation(train_apks,test_apks,data):
    train_data= extract_data(train_apks,data)
    detected=0
    for apk in test_apks:
        test_data = extract_data([apk],data)
        found=False
        for head in test_data:
            if head not in train_data:
                found=True
                break
            else:
                unseen=[e for e in test_data[head] if e not in train_data[head]]
                if len(unseen)>0:
                    found=True
                    break
        if found:
            detected+=1
    return detected


def process(apk_pair_file,data_folder,report_folder):
    with open(apk_pair_file,'r') as reader:
        lines = [l.strip().replace(',',' ').split() for l in reader]
        apk_pairs = [ (e[0],e[-1]) for e in lines]
    data={}
    benign_data={}
    malicious_data={}
    for file_name in os.listdir(data_folder): 
        if not file_name.endswith('.json'):
            continue
        #print(file_name)       
        benign,malicious = file_name[:file_name.find('.')].split('-')
        the_pair = (benign,malicious)
        with open(data_folder+'/'+file_name) as reader:
            jsondata=json.load(reader)
        data[the_pair]=jsondata['diff']
        benign_data[benign]=jsondata['origin']
        malicious_data[malicious]=jsondata['repack']
    
    ###### compute true alarm rates ######
    
    TAR,true_positives,false_negatives,detected_cases,undetected_cases = compute_true_alarms(apk_pairs,data)

    ###### compute false alarm rataes #####

    #FAR,true_negatives,false_positives  = compute_false_alarms(benign_data)

    ####
    print('Baseline-2\t','TP:',true_positives,'FN:',false_negatives)

    #precision,recall,f1 = compute_f1(true_negatives,true_positives,false_negatives,false_positives)

    print('TAR:',TAR,'%')

    ####
    undetected_cases=sorted(undetected_cases)
    detected_cases= sorted(detected_cases)
    if not os.path.isdir(report_folder):
        os.makedirs(report_folder)
    with open(report_folder+'/baselineB_detected_cases.txt','w') as writer:
        detected_cases = map(lambda x: str(x[0])+'\t'+str(x[1]),detected_cases)
        writer.write('\n\n'.join(list(detected_cases))+'\n')    
    with open(report_folder+'/baselineB_undetected_cases.txt','w') as writer:
        undetected_cases = map(lambda x: str(x[0])+'\t'+str(x[1]),undetected_cases)
        writer.write('\n\n'.join(list(undetected_cases))+'\n')

if __name__=='__main__':
    apk_pair_file = 'selected_apps.txt'
    data_folder='sep_ui_diff/1'
    report_folder='reports/baseline_B'
    process(apk_pair_file,data_folder,report_folder)