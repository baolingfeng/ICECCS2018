import os,sys

def process(jar_dir,javap_out_dir,script_file,program_path='/media/duy/DSSD4/ResearchSpace/sandbox_two/SANER_apps/bashscripts/javap.sh',apk_pairs_file=None):
    interested_apk=None
    if apk_pairs_file is not None:
        interested_apk=set()
        with open(apk_pairs_file,'r') as reader:
            for l in reader:
                l = l.strip().replace(',','').split()
                for e in l :
                    if len(e)>0:
                        interested_apk.add(e)
    #############################################################
    cmds=[]
    program_path = os.path.abspath(program_path)
    jar_dir = os.path.abspath(jar_dir)
    javap_out_dir = os.path.abspath(javap_out_dir)
    for jf in os.listdir(jar_dir):
        if not jf.endswith('.jar'):
            continue
        id =  jf[:jf.rfind('.')]
        if interested_apk is not None and id not in interested_apk:
            print("ignore",id)
            continue
        out_file = javap_out_dir+'/'+id+'.txt'
        jf =  jar_dir+'/'+jf
        cmd = 'bash '+program_path+' '+os.path.abspath(jf)+' '+os.path.abspath(out_file)
        cmds+=[cmd]
    with open(script_file,'w') as writer:
        writer.write('\n'.join(cmds))
    

if __name__ =='__main__':
    apk_pairs_file='10small_apps.txt'
    jar_dir='jars'
    javap_out_dir='javap'
    script_file='bashscripts/javap_methodref.sh'

    process(jar_dir,javap_out_dir,script_file,apk_pairs_file=apk_pairs_file)
    
