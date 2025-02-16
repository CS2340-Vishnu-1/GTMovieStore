from django.shortcuts import render
from django.contrib.auth import get_user_model, login as auth_login, authenticate, logout as auth_logout
from .forms import CustomUserCreationForm, CustomErrorList
from django.shortcuts import redirect
from django.contrib.auth.forms import PasswordResetForm, SetPasswordForm
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.template.loader import render_to_string
from django.contrib.auth.decorators import login_required
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.contrib.auth.models import User
@login_required
def logout(request):
    auth_logout(request)
    return redirect('home.index')
def login(request):
    template_data = {}
    template_data['title'] = 'Login'
    if request.method == 'GET':
        return render(request, 'accounts/login.html', {'template_data': template_data})
    elif request.method == 'POST':
        user = authenticate(request, username = request.POST['username'], password = request.POST['password'])
        if user is None:
            template_data['error'] = 'The username or password is incorrect.'
            return render(request, 'accounts/login.html', {'template_data': template_data})
        else:
            auth_login(request, user)
            return redirect('home.index')
def signup(request):
    template_data = {}
    template_data['title'] = 'Sign Up'
    if request.method == 'GET':
        template_data['form'] = CustomUserCreationForm()
        return render(request, 'accounts/signup.html', {'template_data': template_data})
    elif request.method == 'POST':
        form = CustomUserCreationForm(request.POST, error_class=CustomErrorList)
        if form.is_valid():
            form.save()
            return redirect('accounts.login')
        else:
            template_data['form'] = form
            return render(request, 'accounts/signup.html', {'template_data': template_data})

@login_required
def orders(request):
    template_data = {}
    template_data['title'] = 'Orders'
    template_data['orders'] = request.user.order_set.all()
    return render(request, 'accounts/orders.html',
                  {'template_data': template_data})

def password_reset_request(request):
    template_data = {}
    if request.method == "POST":
        form = PasswordResetForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            users = User.objects.filter(email=email)

            if not users.exists():
                template_data['error'] = "No account has this email"
                return render(request, "accounts/password_reset.html", {"form": form, "template_data": template_data})

            for user in users:
                subject = "Password Reset"
                email_template_name = "accounts/password_reset_email.html"
                context = {
                    "email": user.email,
                    "domain": request.get_host(),
                    "site_name": "Your Site Name",
                    "uid": urlsafe_base64_encode(force_bytes(user.pk)),
                    "token": default_token_generator.make_token(user),
                    "protocol": "https" if request.is_secure() else "http",
                }
                email_message = render_to_string(email_template_name, context)
                send_mail(subject, email_message, None, [user.email],html_message=email_message)
            return redirect("accounts.password_reset_sent")
    else:
        form = PasswordResetForm()

    return render(request, "accounts/password_reset.html", {"form": form,  "template_data": template_data})

def password_reset_done(request):
    return render(request, "accounts/password_reset_done.html")

def password_reset_sent(request):
    return render(request, "accounts/password_reset_sent.html")

def password_reset_confirm(request, uidb64, token):
    template_data = {}

    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = get_user_model().objects.get(pk=uid)

        if not default_token_generator.check_token(user, token):
            template_data['error'] = 'The password reset link is invalid or has expired.'
            return render(request, 'accounts/password_reset_confirm.html', {'template_data': template_data})

        if request.method == 'POST':
            form = SetPasswordForm(user, request.POST)
            if form.is_valid():
                form.save()
                template_data['error'] = 'Your password has been reset successfully!'
                return redirect('accounts.password_reset_done')
            else:
                template_data['error'] = 'There was an error with your password reset. Please try again.'

        else:
            form = SetPasswordForm(user)

        return render(request, 'accounts/password_reset_confirm.html', {'form': form, 'template_data': template_data})

    except (TypeError, ValueError, OverflowError, get_user_model().DoesNotExist):
        template_data['error'] = 'The password reset link is invalid or has expired.'
        return render(request, 'accounts/password_reset_confirm.html', {'template_data': template_data})
