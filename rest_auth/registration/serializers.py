from django.http import HttpRequest
from rest_framework import serializers
from requests.exceptions import HTTPError
from allauth.socialaccount.helpers import complete_social_login
from django.core.urlresolvers import NoReverseMatch
from django.db.utils import IntegrityError
from django.contrib.auth import get_user_model


class SocialLoginSerializer(serializers.Serializer):

    access_token = serializers.CharField(required=True)

    def validate(self, attrs):
        access_token = attrs.get('access_token')
        view = self.context.get('view')
        request = self.context.get('request')
        if not isinstance(request, HttpRequest):
            request = request._request

        if not view:
            raise serializers.ValidationError(
                'View is not defined, pass it as a context variable'
            )

        self.adapter_class = getattr(view, 'adapter_class', None)

        if not self.adapter_class:
            raise serializers.ValidationError('Define adapter_class in view')

        self.adapter = self.adapter_class()
        app = self.adapter.get_provider().get_app(request)
        token = self.adapter.parse_token({'access_token': access_token})
        token.app = app

        try:
            login = self.adapter.complete_login(request, app, token,
                                                response=access_token)

            login.token = token
            complete_social_login(request, login)
        except HTTPError:
            raise serializers.ValidationError('Incorrect value')
        except NoReverseMatch:
            """
            Here we catch because all_auth wants to send us to a signup form
            to enter a new email address
            """
            pass
        if not login.is_existing:
            login.lookup()
            try:
                login.save(request, connect=True)
            except IntegrityError:
                """
                here we catch the IntegrityError because there is already an
                user with the same email address.
                Therefore we save login.account on our own and relate it to the
                already registered user
                """
                user = get_user_model().objects.get(
                    email=login.account.extra_data['email']
                )
                login.account.user = user
                login.account.save()
        attrs['user'] = login.account.user

        return attrs
