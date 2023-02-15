from graphene_django.types import DjangoObjectType
import graphene
import graphql_jwt
from graphql_jwt.decorators import login_required

from .models import User
from .util import check_verify_code, create_user, send_verify_code, set_new_password


class UserType(DjangoObjectType):
    class Meta:
        model = User
        fields = ('email', 'username', 'is_active', 'is_admin')


class UserQuery(graphene.ObjectType):
    user = graphene.Field(UserType)

    @login_required
    def resolve_user(self, info):
        return info.context.user


class CreateUser(graphene.Mutation):
    ok = graphene.Boolean(default_value=False)

    class Arguments:
        email = graphene.String(required=True)
        username = graphene.String(required=True)
        password = graphene.String(required=True)

    @staticmethod
    def mutate(cls, info, email, username, password):
        user = create_user(email, username, password)
        return CreateUser() if user is None else CreateUser(ok=True)


class VerifyUser(graphene.Mutation):
    ok = graphene.Boolean(default_value=False)

    class Arguments:
        code = graphene.Int(required=True)
        email = graphene.String(required=False)

    @staticmethod
    def mutate(cls, info, code, email):
        is_check = check_verify_code(email, code)
        return VerifyUser(ok=True) if is_check else VerifyUser()


class ResetPassword(graphene.Mutation):
    ok = graphene.Boolean(default_value=False)

    class Arguments:
        email = graphene.String(required=True)

    @staticmethod
    def mutate(cls, info, email):
        is_send = send_verify_code(email)
        return CreateUser(ok=True) if is_send else CreateUser()


class ResetConfirmPassword(graphene.Mutation):
    ok = graphene.Boolean(default_value=False)

    class Arguments:
        code = graphene.Int(required=True)
        email = graphene.String(required=True)
        new_password = graphene.String(required=True)

    @staticmethod
    def mutate(cls, info, code, email, new_password):
        is_set = set_new_password(code, email, new_password)
        return ResetConfirmPassword(ok=True) if is_set else ResetConfirmPassword()


class UserMutation(graphene.ObjectType):
    verify_user = VerifyUser.Field()
    create_user = CreateUser.Field()
    reset_password = ResetPassword.Field()
    reset_confirm_password = ResetConfirmPassword.Field()
    token_auth = graphql_jwt.ObtainJSONWebToken.Field()
    verify_token = graphql_jwt.Verify.Field()
    refresh_token = graphql_jwt.Refresh.Field()

