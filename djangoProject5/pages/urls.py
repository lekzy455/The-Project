from django.conf.urls import url
from . import views
urlpatterns = [
    #url('api/get_c1', views.get_ksn, name='get_ksn'),
    #url('api/decryptpin', views.decryptpin, name='decryptpinb'),
    #url('api/get_ksn', views.get_ksn, name='get_ksn'),
    url('api/decryptcarddata', views.decryptcarddata, name='decryptcarddata'),
]
