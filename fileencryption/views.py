import mimetypes

from cryptography.fernet import Fernet
from django.core.files.base import ContentFile, File
from django.shortcuts import render
from .utils import generate_key, encrypt_file
from .models import EncryptedFile, KeyFile
from .utils import encrypt_file, decrypt_file
import os
from django.conf import settings
from django.http import FileResponse, HttpResponse
from django.shortcuts import render

def encrypt_file(file_content, key):
    cipher = Fernet(key)
    encrypted_data = cipher.encrypt(file_content)
    return encrypted_data


def decrypt_file(encrypted_data, key):
    cipher = Fernet(key)
    decrypted_data = cipher.decrypt(encrypted_data)
    return decrypted_data


def encrypt_file_view(request):
    if request.method == 'POST':
        file = request.FILES['file']

        # Generate a new key for each encryption (you might want to store this key securely)
        encryption_key = Fernet.generate_key()

        # Read the file content
        file_content = file.read()

        # Encrypt the file content
        encrypted_data = encrypt_file(file_content, encryption_key)

        # Save the encrypted file to the encrypted folder
        encrypted_folder = os.path.join(settings.MEDIA_ROOT, 'encrypted')
        encrypted_file_path = os.path.join(encrypted_folder, file.name + '_encrypted')
        with open(encrypted_file_path, 'wb') as encrypted_file:
            encrypted_file.write(encrypted_data)

        # Save the encryption key to use during decryption
        # You might want to securely store or manage keys in a real-world scenario
        key_file_path = os.path.join(encrypted_folder, file.name + '_key.txt')
        with open(key_file_path, 'wb') as key_file:
            key_file.write(encryption_key)
        encrypted_file_name = os.path.basename(encrypted_file_path)
        return render(request, 'success.html', {'encrypted_file_name': encrypted_file_name})
        # return render(request, 'success.html', {'encrypted_file_path':os.path.basename(encrypted_file_path)})

    return render(request, 'encrypt.html')

def download_encrypted_file(request, encrypted_file_name):
    encrypted_folder = os.path.join(settings.MEDIA_ROOT, 'encrypted')
    encrypted_file_path = os.path.join(encrypted_folder, encrypted_file_name)

    content_type, encoding = mimetypes.guess_type(encrypted_file_path)

    # Use FileResponse for efficient file streaming
    response = FileResponse(open(encrypted_file_path, 'rb'), content_type=content_type)
    response['Content-Disposition'] = f'attachment; filename="{os.path.basename(encrypted_file_path)}"'
    return response


def decrypt_file_view(request, encrypted_file_name):
    encrypted_folder = os.path.join(settings.MEDIA_ROOT, 'encrypted')
    encrypted_file_path = os.path.join(encrypted_folder, encrypted_file_name)

    # Read the encrypted file
    with open(encrypted_file_path, 'rb') as encrypted_file:
        encrypted_data = encrypted_file.read()

    # Read the key file
    key_file_path = os.path.join(encrypted_folder, encrypted_file_name.replace('_encrypted', '_key.txt'))
    with open(key_file_path, 'rb') as key_file:
        encryption_key = key_file.read()

    # Decrypt the file content
    decrypted_data = decrypt_file(encrypted_data, encryption_key)

    # Respond with the decrypted content
    response = HttpResponse(decrypted_data, content_type='application/pdf')  # Adjust content_type based on your file type
    response['Content-Disposition'] = f'attachment; filename={encrypted_file_name.replace("_encrypted", "")}'
    return response





