from random import randint
from django.conf import settings
import datetime
from .models import Opt, User
from django.db.models import Q


def get_user(user_id=None, email=None, username=None):
    try:
        if user_id is not None:
            user = User.objects.get(id=user_id)
            return user
        if email is not None:
            user = User.objects.get(email=email)
            return user
        if username is not None:
            user = User.objects.get(username=username)
            return user
    except User.DoesNotExist:
        return None


def get_opt(user):
    try:
        opt = Opt.objects.get(user=user)
        return opt
    except Opt.DoesNotExist:
        return None


def check_time(opt):
    result = opt.create_at + datetime.timedelta(seconds=settings.TIME_REGISTER_VERIFY_CODE)
    if result.timestamp() > datetime.datetime.now().timestamp():
        return True


def send_verify_code(email):
    user = get_user(email=email)
    if user is not None:
        code = randint(1120, 9980)
        opt = get_opt(user)
        if opt is not None:
            if check_time(opt):
                return None
            opt.delete()
        Opt.objects.create(code=code, user=user)
        # TODO function send(email or mobile)
        return True


def check_verify_code(email, code):
    user = get_user(email=email)
    opt = get_opt(user=user)

    if user is not None and opt is not None:
        if check_time(opt):
            print("time ok")
            if opt.code == code:
                print("code ok")
                user.is_active = True
                user.save()
                opt.delete()
                return True
        else:
            opt.delete()
            if not user.is_active:
                user.delete()


def final_create_user(email, username, password):
    user = User.objects.create_user(email=email, username=username, password=password)
    send_verify_code(email)
    return user


def create_user(email, username, password):
    user = User.objects.filter(Q(email=email) | Q(username=username))
    if not user.exists():
        return final_create_user(email, username, password)
    else:
        print(user)
        if not user.first().is_active:
            opt = Opt.objects.filter(user=user.first())
            if not opt.exists():
                user.delete()
                return final_create_user(email, username, password)
            else:
                if not check_time(opt[0]):
                    user.delete()
                    opt.first().delete()
                    return final_create_user(email, username, password)


def set_new_password(code, email, new_password):
    if check_verify_code(email, code):
        user = get_user(email=email)
        user.set_password(new_password)
        user.save()
        return True

