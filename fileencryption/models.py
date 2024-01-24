from django.db import models
from django import forms
# class EncryptedFile(models.Model):
#     file = models.FileField(upload_to='uploads/')
#     encrypted_file = models.FileField(upload_to='encrypted/')
    # decrypted_file = models.FileField(upload_to='decrypted/', null=True, blank=True)
    # Add more fields as needed

# class DecryptFileForm(forms.Form):
#     encrypted_file = forms.FileField(label='Select Encrypted File')

from django.db import models

class EncryptedFile(models.Model):
    file = models.FileField(upload_to='uploads/')
    encrypted_file = models.FileField(upload_to='encrypted/')
    key_file = models.FileField(upload_to='keys/', default=b'')

class KeyFile(models.Model):
    file = models.FileField(upload_to='keys/')
    key_file = models.FileField(upload_to='keys/')