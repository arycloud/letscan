from flask import Flask, redirect, url_for, flash, render_template, session, make_response
from flask_login import login_required, logout_user
from flask_dance.contrib.google import google
import oauthlib
from oauthlib.oauth2.rfc6749.errors import InvalidClientIdError, TokenExpiredError
from flask_socketio import SocketIO
import nmap

from .config import Config
from .models import db, login_manager
from .oauth import blueprint
from .cli import create_db

socketio = SocketIO(manage_session=False)

app = Flask(__name__)
app.config.from_object(Config)
app.register_blueprint(blueprint, url_prefix="/login")
app.cli.add_command(create_db)

db.init_app(app)
socketio.init_app(app)
login_manager.init_app(app)


@app.route("/logout")
def logout():
    """
    This endpoint tries to revoke the token
    and then it clears the session
    """
    if google.authorized:
        try:
            google.get(
                'https://accounts.google.com/o/oauth2/revoke',
                params={
                    'token':
                        app.blueprints['google'].token['access_token']},
            )
            print('try was ok:')
        except TokenExpiredError:
            pass
        except InvalidClientIdError:
            # Our OAuth session apparently expired. We could renew the token
            # and logout again but that seems a bit silly, so for now fake
            # it.
            logout_user()
            flash('You have been logged out successfully!')
            redirect(url_for('index'))
    _empty_session()
    flash('You have been logged out successfully!')
    return redirect(url_for('index'))



def _empty_session():
    """
    Deletes the google token and clears the session
    """
    if 'google' in app.blueprints and hasattr(app.blueprints['google'], 'token'):
        del app.blueprints['google'].token
    session.clear()

@app.errorhandler(oauthlib.oauth2.rfc6749.errors.TokenExpiredError)
@app.errorhandler(oauthlib.oauth2.rfc6749.errors.InvalidClientIdError)
def token_expired(_):
    _empty_session()
    return redirect(url_for('index'))



@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan")
@login_required
def scan():
    if not google.authorized:
        return redirect(url_for("google.login"))
    return render_template("scan.html")


@app.route('/term-of-service')
def tos():
    return render_template('terms_of_service.html')

# @socketio.on('start_scan')
# def handle_scan(data):
#     print('handle_scan func is called')
#     target = data.get('target')
#     scan_type = data.get('scan_type')
#     ports = data.get('ports')
#     osDetection = data.get('os_detection')

#     nm = nmap.PortScanner()

#     try:
#         if ports == "common":
#             if scan_type == 'tcp':
#                 nm.scan(target, arguments='-sT')
#             elif scan_type == 'udp':
#                 nm.scan(target, arguments='-sU')
#             elif scan_type == 'syn':
#                 nm.scan(target, arguments='-sS')
#         else:
#             port_argument = ','.join(ports.split(','))
#             if scan_type == 'tcp':
#                 nm.scan(target, arguments=f'-sT -p {port_argument}')
#             elif scan_type == 'udp':
#                 nm.scan(target, arguments=f'-sU -p {port_argument}')
#             elif scan_type == 'syn':
#                 nm.scan(target, arguments=f'-sS -p {port_argument}')

#         if nm.all_hosts():
#             for host in nm.all_hosts():
#                 print(nm[host])
#                 host_info = {
#                     'host': host,
#                     'hostname': nm[host].hostname(),
#                     'status': nm[host].state(),
#                     'ports': [
#                         {
#                             'port': port,
#                             'state': nm[host][proto][port]['state'],
#                             'service': nm[host][proto][port]['name'],
#                             'protocol': proto
#                         } for proto in nm[host].all_protocols() for port in nm[host][proto]
#                     ]
#                 }
#                 # print('ports below')
#                 # print(host_info['ports'])
#                 socketio.emit('scan_progress', host_info)
            
#             # Send scan completion with summary data
#             # summary_data = {
#             #     'host': target,
#             #     'ports': ports.split(','),
#             #     'hosts': nm.all_hosts(),
#             #     'startTime': 'N/A',  # Replace with actual timing
#             #     'finishTime': 'N/A',  # Replace with actual timing
#             #     'duration': 'N/A'  # Replace with actual duration
#             # }
#             # socketio.emit('scan_complete', {'message': 'Scan complete', 'summary': summary_data})
#             socketio.emit('scan_complete', {
#                 'message': 'Scan complete',
#                 'summary': {
#                     'host': target,
#                     'ports': host_info['ports'],  # Already a list of dictionaries
#                     'raw_ports': ', '.join([str(port['port']) for port in host_info['ports']]),  # Get a comma-separated string of ports
#                     'hosts': nm.all_hosts(),
#                     'startTime': 'N/A',  # Replace with actual timing
#                     'finishTime': 'N/A',  # Replace with actual timing
#                     'duration': 'N/A'
#                 }
#             })
#             print("Emitted scan_complete: Scan complete")
#         else:
#             socketio.emit('scan_error', {'error': 'No hosts found. Please check the target.'})

#     except Exception as e:
#         error_message = str(e).replace('\n', ' ').strip()
#         socketio.emit('scan_error', {'error': error_message})


@socketio.on('start_scan')
def handle_scan(data):
    print('handle_scan func is called')
    target = data.get('target')
    scan_type = data.get('scan_type')
    ports = data.get('ports')
    osDetection = data.get('os_detection')
    print(f'OS Detection is: {osDetection}')

    nm = nmap.PortScanner()
    nmap_arguments = '-T4 '

    # Add service version detection if OS detection is requested
    if osDetection == "on":
        nmap_arguments += '-sV '  # Gather version information about services

    try:
        # Construct the scan command based on type and ports
        if ports == "common":
            if scan_type == 'tcp':
                nm.scan(target, arguments=nmap_arguments + '-sT')
            elif scan_type == 'udp':
                nm.scan(target, arguments=nmap_arguments + '-sU')
            elif scan_type == 'syn':
                nm.scan(target, arguments=nmap_arguments + '-sS')
        else:
            port_argument = ','.join(ports.split(','))
            if scan_type == 'tcp':
                nm.scan(target, arguments=nmap_arguments + f'-sT -p {port_argument}')
            elif scan_type == 'udp':
                nm.scan(target, arguments=nmap_arguments + f'-sU -p {port_argument}')
            elif scan_type == 'syn':
                nm.scan(target, arguments=nmap_arguments + f'-sS -p {port_argument}')

        # Check if any hosts are found
        if nm.all_hosts():
            for host in nm.all_hosts():
                print(nm[host])  # This should print the host's scan result
                os_info = nm[host].get('osclass', [])
                os_details = []

                # Collect OS details if available
                if os_info:
                    for os_entry in os_info:
                        os_details.append({
                            'osfamily': os_entry.get('osfamily', 'Unknown'),
                            'osgen': os_entry.get('osgen', 'Unknown'),
                            'accuracy': os_entry.get('accuracy', 'Unknown'),
                        })
                print(f'OS Details: {os_details}')

                host_info = {
                    'host': host,
                    'hostname': nm[host].hostname(),
                    'status': nm[host].state(),
                    'ports': [
                        {
                            'port': port,
                            'state': nm[host][proto][port]['state'],
                            'service': nm[host][proto][port]['name'],
                            'product': nm[host][proto][port].get('product', 'Unknown'),
                            'version': nm[host][proto][port].get('version', 'Unknown'),
                            'protocol': proto
                        } for proto in nm[host].all_protocols() for port in nm[host][proto]
                    ],
                    'os': os_details if os_details else 'No OS information available'
                }

                # Emit progress updates to the client
                socketio.emit('scan_progress', host_info)

            # Emit the scan completion summary
            socketio.emit('scan_complete', {
                'message': 'Scan complete',
                'summary': {
                    'host': target,
                    'ports': host_info['ports'],
                    'raw_ports': ', '.join([str(port['port']) for port in host_info['ports']]),
                    'hosts': nm.all_hosts(),
                    'startTime': 'N/A',
                    'finishTime': 'N/A',
                    'duration': 'N/A',
                    'os': host_info['os']
                }
            })
            print("Emitted scan_complete: Scan complete")
        else:
            socketio.emit('scan_error', {'error': 'No hosts found. Please check the target.'})

    except Exception as e:
        error_message = str(e).replace('\n', ' ').strip()
        socketio.emit('scan_error', {'error': error_message})


