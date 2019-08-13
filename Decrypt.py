#share_code = '1947'
#mailid = 'erashru@gmail.com'
#phone_no = '9437607502'

def generate_json(f_name,share_code,mailid,phone_no):

    import xml
    import xml.etree.cElementTree as etree
    from xml.etree import ElementTree
    from base64 import b64encode, b64decode
    from zipfile import ZipFile
    import os
    from glob import glob
    import sys
    import hashlib
    from M2Crypto import BIO, RSA, EVP
    from M2Crypto import X509



    #with ZipFile('Offlineaadhaar.zip') as zf:
    #    zf.extractall(path='xml_folder/',pwd=share_code.encode())

    try:
        zipdata = ZipFile('uploads/' + f_name)
    except:
        return {"Wrong zip file" : 422}
        
    zipinfos = zipdata.infolist()  

    for zipinfo in zipinfos:
        zipinfo.filename = f_name.split('.')[0]+ '.xml'
        try:
            zipdata.extract(zipinfo,path='uploads/',pwd=share_code.encode())
        except RuntimeError:
            return {"Bad sharecode or Zipfile Given" : 422}
    #import os
    #from glob import glob
    #PATH = "uploads/"
    #EXT = "*.xml"
    #xml_path = glob(os.path.join(PATH, EXT))[0]
    import time
    import datetime



    import sys

    #print(xml_path, file=sys.stderr)
    #print(xml_path, file=sys.stdout)
    #print(xml_path)
    xml_path = 'uploads/' + f_name.split('.')[0]+ '.xml'
    xmlDoc = open(xml_path , 'r').read()
    Tr = etree.XML(xmlDoc)

    Tr.keys()


    # Attribute
    # 
    # * Normal  - n(Name), g(Gender), a(Address), d(Date of birth), r(aadhar + timestamp), v(XML version) 
    # * Encrypt - e(Email), m(Mobile no), s(Signeture), i(Image)

    json_dict = dict()
    personal_data = dict()

    # ### Name

    Tr.get('n')
    personal_data['name'] = Tr.get('n')

    # ### Gender
    Tr.get('g')

    personal_data['gender'] = Tr.get('g')


    # ### Date of birth

    s = Tr.get('d')

    import time
    import datetime
    dob = datetime.datetime.strptime(s, "%d%m%Y").strftime('%d/%m/%Y')

    personal_data['dob'] = dob


    # ### Address


    Tr.get('a')
    personal_data['address'] = Tr.get('a')

    # ### Image

    imagestr = Tr.get('i')
    imagestr = bytes(imagestr, 'utf-8')
    personal_data['image'] = Tr.get('i')


    json_dict['personal_data'] = personal_data 


    # ### Last 4 digit Aadhar 

    last_4_digit = Tr.get('r')[:4]
    last_4_digit
    json_dict['Aadhaar_last_4digit']  = 'XXXX-XXXX-' + last_4_digit

    import time
    ts = time.time()
    import datetime
    st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    #print(st)


    json_dict['timestamp'] = st


    validation_dic = dict()


    # ### Email
    # 
    # Logic - Sha256(Sha256(Email+SharePhrase))*number of times last digit of Aadhaar number

    import hashlib
    import sys
     
    def Secure(value,sharecode,laadhar,string):

        value=value+sharecode
        if laadhar == 0:
            laadhar = 1
        
        for x in range(0,laadhar):
            value=hashlib.sha256(value.encode('utf-8')).hexdigest()
            
        if string == value:
            return "Valid"
        else :
            return "Invalid"


    mailstr = Tr.get('e')

    is_valid_mail = Secure(mailid,str(share_code),int(last_4_digit[-1]),mailstr)
    validation_dic['email'] = is_valid_mail
    mobile_str = Tr.get('m')

    is_valid_phone = Secure(phone_no,str(share_code),int(last_4_digit[-1]),mobile_str)
    validation_dic['phone'] = is_valid_phone


    # Digital Signature Validation

    from M2Crypto import BIO, RSA, EVP
    from M2Crypto import X509

    x509 =X509.load_cert('certificate/ekyc_public_key.cer')
    rsa = x509.get_pubkey().get_rsa()
    pubkey = EVP.PKey()
    pubkey.assign_rsa(rsa)

    import lxml.etree as le

    with open(xml_path,'r') as f:
        doc=le.parse(f)
        for elem in doc.xpath('//*[attribute::s]'):
            sign = elem.attrib['s']
            elem.attrib.pop('s')    

    data_str = str(le.tostring(doc))[2:][:-1]
    data = data_str[:-2] +  ' />'
    
    pubkey.reset_context(md='sha256')
    pubkey.verify_init()

    pubkey.verify_update(data.encode())

    is_valid_signeture = ""
    if(pubkey.verify_final(b64decode(sign)) != 1):
        #print('Digital Signeture not validated')
        is_valid_signeture = 'Invalid'
    else: 
        #print('Digital Signeture validated') 
        is_valid_signeture = 'Valid'

    validation_dic['digital_signeture'] = is_valid_signeture

    validation_dic['status'] = 'y'
    validation_dic['Description'] = 'Authenticated Successfully'

    if(is_valid_mail == 'Invalid' or is_valid_phone == 'Invalid' or is_valid_signeture == 'Invalid'): 
        validation_dic['status'] = 'n'
        validation_dic['Description'] = 'Authentication Failed'


    json_dict['validation'] = validation_dic

    import json
    json_data = json.dumps(json_dict)


    return json_dict

#generate_json(share_code,mailid,phone_no)
