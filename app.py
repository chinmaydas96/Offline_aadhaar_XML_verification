from flask import Flask, render_template, request
from werkzeug import secure_filename
from flask_jsonpify import jsonify
from Decrypt import generate_json
import os

app = Flask(__name__)
UPLOAD_FOLDER = './uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER 



@app.route('/upload')
def upload_file():
   return render_template('upload.html')
	
@app.route('/response', methods = ['GET', 'POST'])
def response():
	if request.method == 'POST':
		result = request.form
		try:
			f = request.files['file']
			f_name = (next(request.files.items())[1]).filename
			#print(type(dict(request.files)['file'][0]))
			#print( f)
		except Exception as inst:
			#print()
			return jsonify({"No Zip file selected" : 404})
			 #return jsonify({"No zipfile selected" : 404})

		filename = secure_filename(f_name)
		f.save(os.path.join(app.config['UPLOAD_FOLDER'],filename))
		#return result

		json_string = generate_json(f_name,result['Share_code'],result['MailId'],result['Phone_no'])
		return jsonify(json_string)
		
if __name__ == '__main__':
   app.run(host='0.0.0.0',port='5000',debug = False,threaded=True)
