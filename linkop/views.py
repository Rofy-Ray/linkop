from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, get_object_or_404
from .forms import UserProfileForm, EventForm, CustomUserCreationForm
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from .models import CustomUser, Event, Message, EventReview, Notification
from django.utils import timezone
from django.contrib.auth import get_user_model, authenticate, login, logout
from django.contrib import messages
from django.db.models import Q
from django.db.models.signals import pre_save
from django.dispatch import receiver
from django.core.mail import send_mail
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from django.conf import settings
from django.contrib.auth import views as auth_views
from linkop.templatetags.url_encrypt import encrypt_id

User = get_user_model()

class CustomPasswordResetConfirmView(auth_views.PasswordResetConfirmView):
    def form_invalid(self, form):
        response = super().form_invalid(form)
        if 'new_password2' in form.errors:
            messages.error(self.request, "The passwords you entered do not match. Please try again.")
        return response

def register(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False  
            user.save()
            
            welcome_subject = "What brought you here?"
            welcome_message = f"Hey there!\n\nWe're really glad you've decided to try Linkop! We're Rofy and Kelvin, the founders.\n\nWe're curious: what's happening in your world that brought you to Linkop?\n\n(We're a small startup, and it's always helpful to hear why people signed up).\n\nAlso, how did you hear about us?\n\nThanks,\nRofy & Kelvin\nThe Founders, Linkop"
            from_email = settings.EMAIL_HOST_USER
            to_list = [user.email]
            send_mail(welcome_subject, welcome_message, from_email, to_list, fail_silently=False)
            
            if request.is_secure():
                protocol = 'https'
            else:
                protocol = 'http'

            current_site = get_current_site(request)
            activation_subject = "Activate Your Linkop Account"
            activation_message = render_to_string('email_confirmation.html', {
                'email': user.email,
                'domain': current_site.domain,
                'protocol': protocol,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user)
            })
            send_mail(activation_subject, '', from_email, to_list, fail_silently=False, html_message=activation_message)

            messages.success(request, "Your account has been created successfully! Please check your email to confirm your email address and activate your account. It might be in your spam folder.")
            
            return redirect('login')
        else:
            for field in form:
                for error in field.errors:
                    messages.error(request, f"{field.label}: {error}")
            # if 'password2' in form.errors:
            #     messages.error(request, "The passwords you entered do not match. Please try again.")
    else:
        form = CustomUserCreationForm()
    return render(request, 'registration_form.html', {'form': form})

def activate_account(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = get_user_model().objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, "Your account has been activated!")
        return redirect('login')
    else:
        return redirect('activation_failed')
    
def activation_failed(request):
    return render(request, 'activation_failed.html')

def login_view(request):
    # If the request method is not POST, display the login form
    form = AuthenticationForm()
    return render(request, 'login.html', {'form': form})

def user_login(request):
    User = get_user_model()
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None and user.is_active:
            login(request, user)
            messages.success(request, "You have successfully logged in!")
            if not user.profile_updated:
                return redirect('update_profile')
            else:
                return redirect('home_page')
        else:
            try:
                user = User.objects.filter(email=username).first()
                if user is not None:
                    if not user.is_active:
                        messages.error(request, 'Please check your email and activate your account.')
                    else:
                        messages.error(request, 'Invalid password.')
                else:
                    messages.error(request, 'Email does not exist. Please sign up first.')
            except User.DoesNotExist:
                messages.error(request, 'Email does not exist. Please sign up first.')
            return redirect('login_view')
    else:
        form = AuthenticationForm()
    return render(request, 'login.html', {'form': form})

def user_logout(request):
    logout(request)
    return redirect('home_page')

@login_required
def update_profile(request):
    # current_profile = User.objects.get(id=request.user.id)
    if request.method == 'POST':
        form = UserProfileForm(request.POST, request.FILES, instance=request.user)
        if form.is_valid():
            form.save()
            if not request.user.profile_updated:
                request.user.profile_updated = True
                request.user.save()
                return redirect('home_page')
            else:
                encrypted_user_id = encrypt_id(request.user.id)
                return redirect('user_profile', encrypted_user_id=encrypted_user_id)
            # return render(request, 'user_profile.html', {'user_id': request.user.id})
    else:
        # profile_data = {'first_name': current_profile.first_name, 'last_name': current_profile.last_name, 'fun_fact': current_profile.fun_fact, 'short_bio': current_profile.short_bio}
        form = UserProfileForm(instance=request.user)
    return render(request, 'update_profile.html', {'form': form})

@login_required
def user_profile(request, encrypted_user_id=None):
    user_id = force_str(urlsafe_base64_decode(encrypted_user_id))
    user = get_object_or_404(User, id=user_id)
    past_events = Event.objects.filter(host=user, is_past_event=True)
    # upcoming_events = Event.objects.filter(host=user, is_past_event=False)
    
    is_own_profile = user == request.user
    
    if user == request.user:
        notifications = Notification.objects.filter(user=user, is_read=False)
        senders_with_interest = CustomUser.objects.filter(interests=user)
        has_mutual_interest = None
        can_message_each_other = False
        is_own_profile = True
        
        if not (user.first_name and user.last_name and user.fun_fact and user.short_bio and user.photo):
            return redirect('update_profile') 
    else:
        notifications = None
        senders_with_interest = None
        has_mutual_interest = user in request.user.interests.all() and request.user in user.interests.all()
        can_message_each_other = has_mutual_interest and user != request.user
        is_own_profile = False
            
    return render(request, 'user_profile.html', {'user': user, 'notifications': notifications, 'senders_with_interest': senders_with_interest, 'has_mutual_interest': has_mutual_interest, 'can_message_each_other': can_message_each_other, 'is_own_profile': is_own_profile, 'past_events': past_events})


@login_required
def create_event(request):
    if request.method == 'POST':
        form = EventForm(request.POST)
        if form.is_valid():
            event = form.save(commit=False)
            event.host = request.user
            event.save()
            encrypted_event_id = encrypt_id(event.id)
            return redirect('event_details', encrypted_event_id=encrypted_event_id) 
    else:
        form = EventForm()
    return render(request, 'create_event.html', {'form': form})

@login_required
def update_event(request, encrypted_event_id):
    event_id = force_str(urlsafe_base64_decode(encrypted_event_id))
    event = get_object_or_404(Event, pk=event_id)
    if request.user != event.host:
        return HttpResponseForbidden()
    if request.method == 'POST':
        form = EventForm(request.POST, instance=event)
        if form.is_valid():
            form.save()
            messages.success(request, 'Event updated successfully.')
            encrypted_event_id = encrypt_id(event.id)
            return redirect('event_details', encrypted_event_id=encrypted_event_id)
    else:
        form = EventForm(instance=event)
    return render(request, "create_event.html", {"form": form, "event": event})


def event_details(request, encrypted_event_id):
    event_id = force_str(urlsafe_base64_decode(encrypted_event_id))
    event = get_object_or_404(Event, pk=event_id)
    is_event_host = event.is_host(request.user)
    has_toggled_interest = request.user in event.interested_users.all()
    
    if event.is_past_event:
        # Fetch reviews for the event
        reviews = EventReview.objects.filter(event=event)

        # Check if the user has already reviewed the event
        user_review = EventReview.objects.filter(event=event, reviewer=request.user).first()
        
        if is_event_host:
            user_review = None

        if request.method == 'POST':
            rating = int(request.POST.get('rating'))
            comment = request.POST.get('comment')

            if rating and comment:
                # Create or update the user's review for the event
                if user_review:
                    user_review.rating = rating
                    user_review.comment = comment
                    user_review.save()
                else:
                    review = EventReview(event=event, reviewer=request.user, rating=rating, comment=comment)
                    review.save()

        return render(request, 'event_details.html', {'event': event, 'is_event_host': is_event_host, 'has_toggled_interest': has_toggled_interest, 'reviews': reviews, 'user_review': user_review})
    
    return render(request, 'event_details.html', {'event': event, 'is_event_host': is_event_host, 'has_toggled_interest': has_toggled_interest})

@receiver(pre_save, sender=Event)
def set_event_status(sender, instance, **kwargs):
    now = timezone.now().date()
    if instance.date < now:
        instance.is_past_event = True
    else:
        instance.is_past_event = False

def home_page(request):
    if request.user.is_authenticated and not (request.user.first_name and request.user.last_name and request.user.fun_fact and request.user.short_bio and request.user.photo):
        return redirect('update_profile')
    # Filter events that have a date greater than or equal to today's date
    upcoming_events = Event.objects.filter(date__gte=timezone.now().date()).order_by('date', 'time')
    for event in upcoming_events:
        if len(event.description) > 100:
            event.description = event.description[:125] + '...'

    return render(request, 'home_page.html', {'upcoming_events': upcoming_events})

@login_required
def toggle_interest(request, encrypted_event_id):
    event_id = force_str(urlsafe_base64_decode(encrypted_event_id))
    event = get_object_or_404(Event, pk=event_id)
    if request.user in event.interested_users.all():
        event.interested_users.remove(request.user)
    else:
        event.interested_users.add(request.user)
        
    return redirect('event_details', encrypted_event_id=encrypted_event_id) 

def event_attendees(request, encrypted_event_id):
    event_id = force_str(urlsafe_base64_decode(encrypted_event_id))
    event = get_object_or_404(Event, pk=event_id)
    attendees = event.interested_users.all()
    return render(request, 'event_attendees.html', {'event': event, 'attendees': attendees})

@login_required
def delete_event(request, encrypted_event_id):
    event_id = force_str(urlsafe_base64_decode(encrypted_event_id))
    event = get_object_or_404(Event, pk=event_id)
    if request.user != event.host:
        return HttpResponseForbidden()
    if request.method == 'POST':
        event.delete()
        messages.success(request, 'Event deleted successfully.')
        return redirect('home_page')

@login_required
def pick_interest(request, encrypted_user_id):
    user_id = force_str(urlsafe_base64_decode(encrypted_user_id))
    other_user = get_object_or_404(User, pk=user_id)

    if request.user == other_user:
        # A user cannot pick interest in themselves
        return redirect('user_profile', encrypted_user_id=encrypted_user_id)
    
    if request.method == 'POST':
        toggle_action = request.POST.get('toggle_interest')
        if toggle_action == 'unpick':
            request.user.interests.remove(other_user)
        elif toggle_action == 'pick':
            request.user.interests.add(other_user)
            Notification.objects.create(user=other_user, content=f"{request.user.first_name} {request.user.last_name} has shown interest in you.", sender=request.user)
            messages.success(request, f"You have shown interest in {other_user.first_name} {other_user.last_name}.")
            
            # Check if the receiver is the current user, and if so, display the notification
            if other_user == request.user:
                notifications = Notification.objects.filter(user=other_user, is_read=False)
                return render(request, 'user_profile.html', {'user': other_user, 'notifications': notifications})

        return redirect('user_profile', encrypted_user_id=encrypted_user_id)

    return redirect('user_profile', encrypted_user_id=encrypted_user_id)

@login_required
def mark_notification_as_read(request, encrypted_user_id, encrypted_notification_id):
    notification_id = force_str(urlsafe_base64_decode(encrypted_notification_id))
    notification = get_object_or_404(Notification, pk=notification_id, user=request.user)
    if notification.user == request.user:
        notification.is_read = True
        notification.save()
        encrypted_user_id = encrypt_id(request.user.id)
    return redirect('user_profile', encrypted_user_id=encrypted_user_id)

@login_required
def send_message(request, encrypted_receiver_id):
    receiver_id = force_str(urlsafe_base64_decode(encrypted_receiver_id))
    receiver = get_object_or_404(User, pk=receiver_id)

    if request.method == 'POST':
        content = request.POST.get('content')
        if content:
            message = Message(sender=request.user, receiver=receiver, content=content)
            message.save()

    return redirect('user_profile', encrypted_user_id=encrypted_receiver_id)

@login_required
def reply_to_message(request, encrypted_sender_id):
    sender_id = force_str(urlsafe_base64_decode(encrypted_sender_id))
    sender = get_object_or_404(User, pk=sender_id)

    if request.method == 'POST':
        content = request.POST.get('content')
        if content:
            message = Message(sender=request.user, receiver=sender, content=content)
            message.save()

    return redirect('message_history', encrypted_sender_id=encrypted_sender_id)

@login_required
def message_inbox(request):
    senders = User.objects.filter(
        sent_messages__receiver=request.user
    ).distinct()
    return render(request, 'message_inbox.html', {'senders': senders})

@login_required
def message_history(request, encrypted_sender_id):
    sender_id = force_str(urlsafe_base64_decode(encrypted_sender_id))
    sender = get_object_or_404(User, pk=sender_id)
    
    # Get messages between the logged-in user and the sender
    messages = Message.objects.filter(
        (Q(sender=request.user) & Q(receiver=sender)) | (Q(sender=sender) & Q(receiver=request.user))
    ).order_by('timestamp')

    return render(request, 'message_history.html', {'sender': sender, 'messages': messages})


@login_required
def rate_and_review_event(request, encrypted_event_id):
    event_id = force_str(urlsafe_base64_decode(encrypted_event_id))
    event = get_object_or_404(Event, pk=event_id)

    if request.method == 'POST':
        rating = int(request.POST.get('rating'))
        comment = request.POST.get('comment')

        if rating and comment:
            review = EventReview(event=event, reviewer=request.user, rating=rating, comment=comment)
            review.save()

    return redirect('event_details', encrypted_event_id=encrypted_event_id)