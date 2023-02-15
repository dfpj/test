import graphene
from account.schema import UserQuery, UserMutation


class Query(UserQuery, graphene.ObjectType):
    pass


class Mutation(UserMutation, graphene.ObjectType):
    pass


my_schema = graphene.Schema(query=Query, mutation=Mutation)

