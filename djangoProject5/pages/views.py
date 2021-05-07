# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.shortcuts import render
from django.http import HttpResponse, HttpResponseBadRequest, JsonResponse
from pages.app import hextostring, decrypt_card_info, decrypt_pinblock
#from django.core.serializers import json
from django.views.decorators.csrf import csrf_exempt
#import ksn
import json

#KSN = "00119112000765e0001f"
#DATA = "a8a83c06523089dd7729708d1a67defedc6ad370915120380822d240d2591a1c386fc19f4ee346ae9854f295544d7f21e63f143d0bf9fb4eeb0c3db7075a4308cd5d2ec70a27d28e"
# DATA="153CEE49576C0B709515946D991CB48368FEA0375837ECA6"
# a=decrypt_card_info(KSN,DATA)
# c=hextostring(a)
# x=c[2:18]
# y=c[19:25]
# q=c[26:32]

#KSN_Value = None


""" @csrf_exempt
def get_c1(request):
    if request.method != 'POST':
        return JsonResponse({"Supported Request Methods": ["POST"]})
    else:
        # KSN=request.body
        # print(request)
        #test = json.loads(request.body)
        print(ksn.ksntable)
        body = json.loads(request.body)
        # print(body["ksn"])
        txnid = body["txnid"]
        Tsnid = body["ksn"]
        (ksn.ksntable)[txnid] = Tsnid
        print(ksn.ksntable)
        # print(ksn)
    return HttpResponse(Tsnid)


@csrf_exempt
def decryptpin(request):
    if request.method != 'POST':
        return JsonResponse({"Supported Request Methods": ["POST"]})
    else:
        body = json.loads(request.body)
        print(body)
        print(ksn.ksntable)
        DAT = body["data"]
        txnid = body["txnid"]
        Tsnid = (ksn.ksntable)[txnid]
        try:
            print("Using KSN: " + Tsnid)
            pins = decrypt_pinblock(Tsnid, DAT)
            ksn.ha = {
                'pin': pins,
                'txnid': txnid
            }
            #s = h['pin']
            #txnid = h['txnid']
            # print(ksn.h)[txnid]
            print(ksn.ha)
            #s = ha["pin"]
            #taa = ha["txnid"]
            # print(ksn.h)[taa]
            print(ksn.ha["pin"])
            print(ksn.ha)
            tyu = JsonResponse(ksn.ha)
            print(tyu)
            # pins=tyu["pin"]
            # txnid=tyu["txnid"]

            return(tyu)
        except Exception as e:
            return JsonResponse("An error occured while decrypting the card info: " + e.message, safe=False)


@csrf_exempt
def get_ksn(request):
    if request.method != 'POST':
        return JsonResponse({"Supported Request Methods": ["POST"]})
    else:
        # KSN=request.body
        # print(request)
        #test = json.loads(request.body)
        print(ksn.ksntable)
        body = json.loads(request.body)
        # print(body["ksn"])
        txnid = body["txnid"]
        ksnid = body["ksn"]
        (ksn.ksntable)[txnid] = ksnid
        print(ksn.ksntable)
        # print(ksn)
    return HttpResponse(ksnid) """


@csrf_exempt
def decryptcarddata(request):
    if request.method != 'POST':
        return JsonResponse({"Supported Request Methods": ["POST"]})
    else:
        try:
            body = json.loads(request.body)
            print(body)
            print(ksn.ksntable)
            DATA = body["carddata"]
            ksnid = body["cardksn"]
            Pin_Data = body["pindata"]
            Pin_Ksn = body["pinksn"]
            #txnid = body["txnid"]
            #ksnid = (ksn.ksntable)[txnid]
            # KSN=request.body
        
            print("Using KSN: " + ksnid)
            pins = decrypt_pinblock(Pin_Ksn, Pin_Data)
            a = decrypt_card_info(ksnid, DATA)
            Pan_tag = a.find('5a')
            name_tag = a.find('5f20')
            w = a.find('5f24')
            u = a[Pan_tag+4:Pan_tag+20]
            #tr = ksn.ha["pin"]
            tr = pins
            q = str(u)
            yw = '0000'+q[4:]
            y_hex = int(yw, 16)
            v_hex = int(tr, 16)
            m = hex(y_hex ^ v_hex)
            # print(m)
            # print(m[3:7])
            t = a[w+6:w+12]
            n = a[name_tag+6:name_tag+40]
            name = hextostring(n)

            r = {
                'card_pan': u,
                'card_holders_name': name,
                'expirydate': t,
                'cardpin': m[3:7],
                "response_code": '00'
            }
            return JsonResponse(r)
        except Exception as e:
            r = {"response_code": '01',
                 "response_description": "An error occured while decrypting the card info: " + e.message}
            return JsonResponse(r, safe=False)
   # DATA={}
   # if request.META.get('CONTENT_TYPE', '').lower() =='application/json' and len(request.body) > 0:
          # try:
            #body_unicode = request.body.decode('utf-8')
            #DATA = json.loads(body_unicode)
          # except Exception as e:
            # return HttpResponseBadRequest(json.dumps({'error': 'Invalid request: {0}'.format(str(e))}), content_type="application/json")
    # DATA=input("")
    # DATA="a8a83c06523089dd7729708d1a67defedc6ad370915120380822d240d2591a1c386fc19f4ee346ae9854f295544d7f21e63f143d0bf9fb4eeb0c3db7075a4308cd5d2ec70a27d28e"

    # return JsonResponse(r)
