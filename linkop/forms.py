from django import forms
from .models import CustomUser, Event
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from bootstrap_datepicker_plus.widgets import DatePickerInput, TimePickerInput

User = get_user_model()

class UserProfileForm(forms.ModelForm):
    first_name = forms.CharField(required=True)
    last_name = forms.CharField(required=True)
    class Meta:
        # app_label = 'linkop'
        model = User
        fields = ['first_name', 'last_name', 'photo', 'fun_fact', 'short_bio']
        
class EventForm(forms.ModelForm):
    class Meta:
        model = Event
        fields = ['title', 'description', 'date', 'time', 'location']
        widgets = {
            'date': DatePickerInput(format='%m/%d/%Y'),
            'time': TimePickerInput(format='%H:%M'),
        }
        
class CustomUserCreationForm(UserCreationForm):
    class Meta:
        model = User
        fields = ("email",)

class CustomUserChangeForm(UserChangeForm):
    class Meta:
        model = User
        fields = ("email",)
        