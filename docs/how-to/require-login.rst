How To require authentication with a nice API
=============================================

Django uses python exceptions when a page is not found or when a permission is
denied.

For example::

    def my_view(request, pk):
        try:
            Model.objects.get(pk=pk)
        except Model.DoesNotExist:
            raise Http404
        # ...

This doesn't really make sense in a function-based views, because we could've
written this::

    def my_view(request, pk):
        try:
            Model.objects.get(pk=pk)
        except Model.DoesNotExist:
            return HttpNotFoundResponse()
        # ...


However, it becomes extremely powerful in `class-based views
<https://docs.djangoproject.com/en/dev/topics/class-based-views/>`_.

If we port our previous example to class-based views, we get::

    class SingleObjectMixin(object):
        # ...
        def get_object(self):
            queryset = self.get_queryset()
            try:
                queryset.get(pk=pk)
            except self.model.DoesNotExist:
                raise Http404("The object with this id doesn't exist.")
        # ...

``django.core.exceptions.PermissionDenied`` works the same way.


Django-authtools gives you the ability to do raise python exceptions in order
to require an authentication.

First of all, you have to enable the middleware
``LoginRequiredHandlerMiddleware`` in your
``settings.py``::

    MIDDLEWARE_CLASSES += ('authtools.middleware.LoginRequiredHandlerMiddleware', )

Once you did this, you can raise ``LoginRequired`` in any place. After
authenticating, It will redirect the user to the view the exception has been
raised from.

For example::

    from authtools.exceptions import LoginRequired


    class MyView(DetailView):
        def get_object(self):
            obj = super(MyView, self).get_object()
            if self.request.user.is_anonymous() and not obj.is_public:
                raise LoginRequired
            return obj


By default, it will redirect back to the url the user is at (query
string included). But you can redirect to another url, a path, or a view::

    class MyView(View):
        def weird_method(self):
            if self.request.user.is_anonymous():
                if self.object.external_redirect:
                    raise LoginRequired('http://www.example.com/object/')
                elif self.object.path:
                    raise LoginRequired('/object/')
                else:
                    raise LoginRequired('myapp.views.my_view')
