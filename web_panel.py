import requests
import json
import uuid
from flask import Flask, render_template, request, flash, redirect, url_for, session

app = Flask(__name__)
app.secret_key = 'asuwishmynigga' 

BOT_API_URL = "http://127.0.0.1:8080/command"

@app.route('/')
def index():
    """Renders the main control panel page."""
    # Initialize session if not exists
    if 'session_id' not in session:
        session['session_id'] = str(uuid.uuid4())
    # Initialize server preference (default to BD)
    if 'preferred_server' not in session:
        session['preferred_server'] = 'BD'
    return render_template('index.html')

@app.route('/action', methods=['POST'])
def handle_action():
    """Handles all form submissions from the new UI."""
    try:
        # Initialize session if not exists
        if 'session_id' not in session:
            session['session_id'] = str(uuid.uuid4())
        if 'preferred_server' not in session:
            session['preferred_server'] = 'BD'
        
        action = request.form.get('action')
        payload_str = request.form.get('payload')
        preferred_server = request.form.get('preferred_server', session.get('preferred_server', 'BD'))
        
        # Update session with preferred server
        session['preferred_server'] = preferred_server
        
        if not action or payload_str is None:
            flash('Invalid request from client.', 'danger')
            return redirect(url_for('index'))

        bot_payload = {
            'action': action,
            'session_id': session['session_id'],
            'preferred_server': preferred_server
        }
        
        data = json.loads(payload_str)

        if action == 'emote':
            bot_payload.update(data)
            if not bot_payload.get('emote_id') or not bot_payload.get('player_ids'):
                raise ValueError("Emote ID and Player IDs are required.")
            flash(f"Sending emote {bot_payload['emote_id']} to {len(bot_payload['player_ids'])} player(s)...", 'success')

        elif action == 'freestyle_emote':
            bot_payload.update(data)
            if (
                not bot_payload.get('emote_id')
                or not bot_payload.get('player_ids')
                or not bot_payload.get('team_code')
            ):
                raise ValueError("Freestyle emote requires an emote, team code, and player IDs.")
            flash(
                f"Triggering freestyle emote {bot_payload['emote_id']} for {len(bot_payload['player_ids'])} target(s)...",
                'success'
            )

        elif action == 'emote_batch':
            # Handle both old format (list) and new format (object with assignments)
            if isinstance(data, list):
                bot_payload['assignments'] = data
            elif isinstance(data, dict) and 'assignments' in data:
                bot_payload.update(data)
            else:
                raise ValueError("A list of assignments or object with assignments is required for emote_batch.")
            assignments = bot_payload.get('assignments', [])
            flash(f"Sending batch of {len(assignments)} assigned emotes...", 'success')
            
        elif action == 'join_squad':
            bot_payload.update(data)
            if not bot_payload.get('team_code'):
                 raise ValueError("Team Code is required.")
            flash(f"Attempting to join squad {bot_payload.get('team_code')}...", 'success')

        elif action == 'quick_invite':
            bot_payload.update(data)
            if not bot_payload.get('player_id'):
                 raise ValueError("Your Main Account UID is required.")
            flash('Creating squad and sending invite...', 'success')

        elif action == 'leave_squad':
            bot_payload.update(data)
            flash('Telling bot to leave squad...', 'info')
        
        else:
            flash(f'Unknown action: {action}', 'danger')
            return redirect(url_for('index'))

        response = requests.post(BOT_API_URL, json=bot_payload, timeout=10)
        
        if response.status_code == 200:
            result = response.json()
            flash(result.get('message', 'Command sent successfully!'), 'success')
        elif response.status_code == 503:
            result = response.json()
            error_msg = result.get('message', 'No available bot')
            if 'session' in error_msg.lower() or 'owned' in error_msg.lower():
                flash('This bot is already controlled by another user session.', 'danger')
            else:
                flash(f"No available bot: {error_msg}", 'danger')
        else:
            result = response.json()
            error_msg = result.get('message', 'Unknown error')
            if 'session' in error_msg.lower() or 'owned' in error_msg.lower():
                flash('You do not have permission to control this bot. It belongs to another user.', 'danger')
            else:
                flash(f"Error from bot: {response.status_code} - {error_msg}", 'danger')

    except requests.exceptions.ConnectionError:
        flash('Could not connect to the bot API. Is main.py running?', 'danger')
    except (ValueError, json.JSONDecodeError) as e:
        flash(f'Invalid data provided: {e}', 'danger')
    except Exception as e:
        flash(f'An unexpected error occurred: {e}', 'danger')

    return redirect(url_for('index'))

@app.route('/set_server', methods=['POST'])
def set_server():
    """Updates the preferred server for the session."""
    server = request.form.get('server', 'BD').upper()
    if server in ['BD', 'PK']:
        session['preferred_server'] = server
        return {'status': 'ok', 'server': server}
    return {'status': 'error', 'message': 'Invalid server'}, 400

if __name__ == '__main__':
    print("Byte Force Bot Web Panel")
    print("Open your web browser and go to http://127.0.0.1:5000")
    print("Make sure main.py is running first!")
    app.run(host='127.0.0.1', port=5000)