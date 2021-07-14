from flask import Flask
from flask_mysqldb import MySQL
from user_module.user import user
# from patient_module.patient_personal import patient_personal
# from patient_module.patient_health import patient_health

app = Flask(__name__)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'raghu'
app.config['MYSQL_DB'] = 'clinicalfirst'


mysql = MySQL(app)

app.register_blueprint(user, url_prefix="/user")
# app.register_blueprint(patient_personal, url_prefix="/patient_personal")
# app.register_blueprint(patient_health, url_prefix="/patient_health")

# default root:-
@app.route("/")
def default():
    return "<h1>Test Message from Empty root !!!</h1>"


# MAIN app To Run the Flask Script:-
if __name__ == "__main__":
    app.run(debug=True)

# When you deploy before to the server:-
# Note:-     app.run(debug=False)
# Make debug value False and deploy the code.