import sys,os,tarfile,itertools
def read_permissions(f):
    with open(f,'r') as reader:
        lines =[l.strip() for l in reader]
    line_index=0
    current_permission = None
    current_method_count = None
    current_method_set = set()
    ans={}
    while line_index < len(lines):
        if lines[line_index].startswith('Permission:'):
            for m in current_method_set:
                ans[m]=current_permission
            
            if current_method_count is not None and len(current_method_set)!=current_method_count:
                print("ERROR: inconsistent number of API methods")
                sys.exit(0)
            
            current_method_set=set()
            current_permission = lines[line_index]
            line_index+=1
            current_method_count = int(lines[line_index].split()[0])
        else:            
            current_method_set.add(lines[line_index])
        #####
        line_index+=1
    #####
    for m in current_method_set:
        ans[m]=current_permission
    return ans

    
def type_conversion(type_str,type_mapping):
    if type_str.startswith('['):
        return type_conversion(type_str[1:],type_mapping)+'[]'
    elif type_str.startswith('L') and type_str.endswith(';'):
        return type_str[1:-1].replace('/','.')
    else:
        return type_mapping[type_str]
def next_para(type_str,p,type_mapping):
    if p>= len(type_str):
        return None,p
    elif type_str[p]  in type_mapping:
        ans = type_str[p]
        p+=1
        return ans,p
    elif type_str[p]=='[':
        ans,np = next_para(type_str,p+1,type_mapping)
        return '['+ans,np
    elif type_str[p]=='L':
        ans=''
        while p < len(type_str) and type_str[p] !=';':
            ans = ans + type_str[p]
            p+=1
        return ans+';',p+1
    else:
        print("ERROR: cannot parse",type_str[p:])

def convert(method,type_mapping={'Z':'boolean','B':'byte','C':'char','S':'short','I':'int','J':'long','F':'float','D':'double','V':'void'}):
    arr= method.split(':')
    if len(arr)<2:
        #print("ERROR:",method)
        return None
    elif len(arr)>2:
        print("ERROR:",method)
        return None
    first,second =arr
    if '.' in first:
        classname, methodname = first.split('.')
    else:
        classname=''
        methodname = first
    methodname=methodname.replace('\"','')
    ####
    return_type =type_conversion(second[second.rfind(')')+1:],type_mapping)
    ####
    parameter_types=second[second.find('(')+1:second.find(')')]
    stack=[]
    pointer = 0
    while True:
        para,pointer  = next_para(parameter_types,pointer,type_mapping)
        if para is None:
            break
        stack+=[type_conversion(para,type_mapping)]
    #####
    classname = classname.replace('/','.')
    rt=      '<'+classname+':'+' '+return_type+' '+methodname+'('+','.join(stack)+')'+'>'
    # print(method,rt)
    return rt


def get_method_signature(clazz_name,name_line):
    loc = name_line.find('(')

    while name_line[loc]!=' ':
        loc-=1
        if loc<0:
            print("ERROR:",name_line)
            sys.exit(0)
    name_paras = name_line[loc+1:-1].replace(' ','')
    second_loc =loc-1
    while name_line[second_loc]!=' ':
        second_loc-=1
    return_type =  name_line[second_loc+1:loc]
    clazz_name=clazz_name.replace('/','.')
    #sign = '<'+clazz_name.replace('/','.')+': '+return_type+' '+name_paras+'>'
    return (clazz_name,return_type,name_paras)
def ok_to_select_method_line(l):
    arr = l.split()
    return len(arr)>=2 and ':' in l and 'invoke' in arr[1]
def parse_invoked_methods( apk_file ):
    tar =tarfile.open(apk_file,'r:bz2')
    #print("Parsing",apk_file)
    ans={}
    for member in tar.getmembers():
        reader = tar.extractfile(member)
        print("Reading",member.name)
        lines=[x.decode('utf8').rstrip()for x in reader]
        class_strings = [ list(s) for o,s in itertools.groupby(lines,lambda x:x=='-------------------------------------------------------') if not o]
        for clazz_string in class_strings:
            clazz_name = clazz_string[0].split()[-1]
            index=0
            while index < len(clazz_string) and clazz_string[index]!='{':
                index+=1
            if index >  len(clazz_string):
                print("Cannot find the open parenthese!")
                sys.exit(0)
            interested_string = clazz_string[index+1:-1] if clazz_string[-1]=='}' else clazz_string[index+1:]
            method_strings = [list(s) for o,s  in itertools.groupby(interested_string,lambda x: len(x.strip())==0) if not o]
            for method_string in method_strings:
                name_line = method_string[0]
                if '(' not in name_line:
                    continue
                sign = get_method_signature(clazz_name,name_line)

                method_calls = set([convert(l.strip().split()[-1]) for l in method_string if ok_to_select_method_line(l) ])
                ans[sign]=method_calls
    return ans

def get_caller_signature(arr):
    clazz_name,return_type,name_paras=arr
    return '<'+clazz_name+': '+return_type+' '+name_paras+'>'

def process(permission_mapping_file,methodref_dir,apk_pairs_file,to_record_folder):
    if not os.path.isfile(apk_pairs_file):
        return
    method2permission = read_permissions(permission_mapping_file)
    #####
    
    with open(apk_pairs_file,'r') as reader:
        pairs=set([tuple(e.replace(',','\t').strip().split()) for e in reader])        
        benign_apks={x[0]:x[1] for x in pairs}
    #print(pairs)
   #####
    methods_with_permissions={}
    for apk_file in os.listdir(methodref_dir):
        
        if not os.path.isfile(methodref_dir+'/'+apk_file):
            print("ERROR: cannot find",methodref_dir+'/'+apk_file)
            sys.exit(0)
            continue

        apk_id = apk_file[:apk_file.find('.')]

        # if apk_id not in benign_apks:
        #     continue

        invoked_methods_mapping=parse_invoked_methods(methodref_dir+'/'+apk_file)
        
        methods_with_permissions[apk_id]={}
        
        for (caller,callees) in invoked_methods_mapping.items():

            sign = get_caller_signature(caller)
            for callee in callees:
                if callee not in method2permission:
                    continue
                p = method2permission[callee]
                if sign not in methods_with_permissions[apk_id]:
                    methods_with_permissions[apk_id][sign]=set()
                methods_with_permissions[apk_id][sign].add(p)
        
        print("APK:",apk_id)
        print("#Methods:",len(methods_with_permissions[apk_id]))
        for m in methods_with_permissions[apk_id]:
            print(m,'\t',methods_with_permissions[apk_id][m])
        print()
        ####
        to_write_list = list(set(methods_with_permissions[apk_id].keys()))
        with open(to_record_folder+'/'+apk_id+'.txt','w')as writer:
            #writer.write('\n'.join(to_write_list))
            for m in methods_with_permissions[apk_id]:
                writer.write(m+'\t'+'\t'.join(methods_with_permissions[apk_id][m])+'\n')
            # with open(to_record_folder+'/'+benign_apks[apk_id]+'.txt','w')as writer:
            #     # writer.write('\n'.join(to_write_list))
            #     for m in methods_with_permissions[benign_apks[apk_id]]:
            #         writer.write(m+'\t'+'\t'.join(methods_with_permissions[apk_id][m])+'\n')
    #####

    found_cases=set()
    for (benign,malicious) in pairs:
        benign_methods_permissions = methods_with_permissions[benign] if benign in methods_with_permissions else {}
        malicious_methods_permissions = methods_with_permissions[malicious] if malicious in methods_with_permissions else {}
        if len(benign_methods_permissions)==0:
            print("WARNING: benign apk have no permission accesses!",benign)
        if len(malicious_methods_permissions)==0:
            print("WARNING: malicious apk have no permission accesses!",malicious)
        warning=False
        for method in malicious_methods_permissions:
            if method not in benign_methods_permissions:
                warning=True
                break
                pass
            else:
                malicious_permissions = malicious_methods_permissions[method]
                benign_permissions = benign_methods_permissions[method]
                if len(malicious_permissions-benign_permissions)>0:
                    warning=True
                    break
        if warning:
            found_cases.add((benign,malicious))
    print("########################")
    for p in found_cases:
        print("PAIR",p[0],p[1])
    print("#FOUND CASES:",len(found_cases))
    


if __name__ == '__main__':
    permission_mapping_file='api_permission_mapping/jellybean_publishedapimapping.txt'
    methodref_dir='javap'
    apk_pairs_file='selected_apps.txt'
    to_record_folder='to_record_methods'
    process(permission_mapping_file,methodref_dir,apk_pairs_file,to_record_folder)
