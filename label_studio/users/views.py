"""This file and its contents are licensed under the Apache License 2.0. Please see the included NOTICE for copyright information and LICENSE for a copy of the license.
"""
import logging
import requests
import json
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, reverse
from django.contrib import auth
from django.conf import settings
from django.core.exceptions import PermissionDenied
from rest_framework.authtoken.models import Token

from users import forms
from core.utils.common import load_func
from core.middleware import enforce_csrf_checks
from users.functions import proceed_registration
from organizations.models import Organization
from organizations.forms import OrganizationSignupForm

from label_studio.core.utils.params import get_env

logger = logging.getLogger()

def get_keycloak_token():
    path = "auth/realms/master/protocol/openid-connect/token"
    url = "{}/{}".format(get_env('KEYCLOAK_HOST'), path)
    data = {
        "client_id": "admin-cli",
        "grant_type": "password",
        "username": get_env('KEYCLOAK_MASTER_USERNAME'),
        "password": get_env('KEYCLOAK_MASTER_PASSWORD')
    }
    r = requests.post(url=url, data=data)
    # print(r)
    if 200 == r.status_code:
        return "bearer {}".format(json.loads(r.content.decode())["access_token"])
    else:
        raise ValueError(r.reason)


def get_user(token, username):
    path = "auth/admin/realms/{}/users".format(get_env('KEYCLOAK_REALM'))
    url = "{}/{}".format(get_env('KEYCLOAK_HOST'), path)
    url += "?username=" + username
    headers = {"authorization": token}
    r = requests.get(url=url,headers=headers)
    if str(r.status_code).startswith("20"):
        logger.info("get_user: {}".format(r.content))
        if r.content != '' and r.content.decode() != '[]':
            return json.loads(r.content.decode())[0]["id"]
        else:
            logger.error("get_user: {}".format(r.content))
            return ""
    else:
        raise ValueError("{}__{}__{}".format(r.status_code, r.reason, r.content))


def logout_keycloak(token, user_id):
    path = "auth/admin/realms/{}/users/{}/logout".format(get_env('KEYCLOAK_REALM'), user_id)
    url = "{}/{}".format(get_env('KEYCLOAK_HOST'), path)
    headers = {"authorization": token}
    r = requests.post(url=url, headers=headers)
    if str(r.status_code).startswith("20"):
        logger.info("logout success".format(r.content))
    else:
        raise ValueError("{}__{}__{}".format(r.status_code, r.reason, r.content))

def logout_keycloak_handler(request):
    user = getattr(request, 'user', None)
    if not getattr(user, 'is_authenticated', True):
        user = None
        return
    token = get_keycloak_token()
    logger.info("================ get keycloak token success ===============")
    user_id = get_user(token, user.username)
    logger.info("================ get keycloak userid: {} ===============".format(user_id))
    if user_id:
        logout_keycloak(token, user_id)


@login_required
def logout(request):
    # logout keycloak
    logger.info("================ start logout keycloak ===============")
    logout_keycloak_handler(request)
    auth.logout(request)

    if settings.HOSTNAME:
        redirect_url = settings.HOSTNAME
        if not redirect_url.endswith('/'):
            redirect_url += '/'
        return redirect(redirect_url)
    return redirect('/')


@enforce_csrf_checks
def user_signup(request):
    """ Sign up page
    """
    user = request.user
    next_page = request.GET.get('next')
    token = request.GET.get('token')
    next_page = next_page if next_page else reverse('projects:project-index')
    user_form = forms.UserSignupForm()
    organization_form = OrganizationSignupForm()

    if user.is_authenticated:
        return redirect(next_page)

    # make a new user
    if request.method == 'POST':
        organization = Organization.objects.first()
        if settings.DISABLE_SIGNUP_WITHOUT_LINK is True:
            if not(token and organization and token == organization.token):
                raise PermissionDenied()

        user_form = forms.UserSignupForm(request.POST)
        organization_form = OrganizationSignupForm(request.POST)

        if user_form.is_valid():
            redirect_response = proceed_registration(request, user_form, organization_form, next_page)
            if redirect_response:
                return redirect_response

    return render(request, 'users/user_signup.html', {
        'user_form': user_form,
        'organization_form': organization_form,
        'next': next_page,
        'token': token,
    })


@enforce_csrf_checks
def user_login(request):
    """ Login page
    """
    user = request.user
    next_page = request.GET.get('next')
    next_page = next_page if next_page else reverse('projects:project-index')
    login_form = load_func(settings.USER_LOGIN_FORM)
    form = login_form()

    if user.is_authenticated:
        return redirect(next_page)

    if request.method == 'POST':
        form = login_form(request.POST)
        if form.is_valid():
            user = form.cleaned_data['user']
            auth.login(request, user, backend='django.contrib.auth.backends.ModelBackend')

            # user is organization member
            org_pk = Organization.find_by_user(user).pk
            user.active_organization_id = org_pk
            user.save(update_fields=['active_organization'])
            return redirect(next_page)

    return render(request, 'users/user_login.html', {
        'form': form,
        'next': next_page
    })


@login_required
def user_account(request):
    user = request.user

    if user.active_organization is None and 'organization_pk' not in request.session:
        return redirect(reverse('main'))

    form = forms.UserProfileForm(instance=user)
    token = Token.objects.get(user=user)

    if request.method == 'POST':
        form = forms.UserProfileForm(request.POST, instance=user)
        if form.is_valid():
            form.save()
            return redirect(reverse('user-account'))

    return render(request, 'users/user_account.html', {
        'settings': settings,
        'user': user,
        'user_profile_form': form,
        'token': token
    })
