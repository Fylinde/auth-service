import click
import requests
from app.database import get_db 

USER_SERVICE_URL = "http://user-service/api/users"

@click.command()
@click.option('--email', prompt='Admin email', help='The email for the admin user')
@click.option('--password', prompt='Admin password', help='The password for the admin user', hide_input=True)
@click.option('--full_name', prompt='Admin full name', help='The full name for the admin user')
@click.option('--phoneNumber', prompt='Admin phone Number', help='The phone number for the admin user')
def create_admin(email, password, full_name, phoneNumber):
    """Create an admin user via CLI by calling the user-service API."""
    try:
        # Make an API call to user-service to create the admin
        response = requests.post(
            f"{USER_SERVICE_URL}/create-admin",
            json={
                "email": email,
                "password": password,
                "full_name": full_name,
                "phoneNumber": phoneNumber,
                "is_admin": True
            }
        )

        if response.status_code == 201:
            click.echo(f"Admin user {full_name} created successfully.")
        else:
            click.echo(f"Failed to create admin user: {response.json().get('detail')}")
    except requests.exceptions.RequestException as e:
        click.echo(f"Error: Could not connect to user-service: {e}")

if __name__ == '__main__':
    create_admin()
