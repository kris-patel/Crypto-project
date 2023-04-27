from django.shortcuts import render, get_object_or_404,redirect
from django.http import HttpResponseRedirect
from .forms import RegistrationForm
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import login,logout,authenticate, update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.decorators import login_required
from .models import Candidate,ControlVote,Position,Votes
from .forms import ChangeForm
import random
import pymongo
import pandas as pd
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import hashlib
from random import getrandbits, randint
import codecs

client = pymongo.MongoClient("mongodb+srv://Kris:1DwQsf8Olmj1eOhW@cluster0.hvo47if.mongodb.net/test")

def select_random_user():
    all_users = User.objects.all()
    selected = list(all_users)
    n = random.randint(4,all_users.count())
    return random.sample(selected,n)

class RingSignature:

    def __init__(self, message, public_keys, signer_index):
        self.message = message
        self.public_keys = public_keys
        self.signer_index = signer_index
        self.n = len(public_keys)
        self.key_size = len(public_keys[0])
        self.mask = self.generate_mask()
        
    def generate_mask(self):
        rand_nums = [random.randint(0, 2**self.key_size-1) for _ in range(self.n)]
        rand_nums[self.signer_index] = 0
        mask = 0
        for i in range(self.n):
            mask ^= int(hashlib.sha256(str(rand_nums[i]).encode()).hexdigest(), 16)
        return mask
        
    def sign(self):
        hashes = [0] * self.n
        for i in range(self.n):
            if i == self.signer_index:
                hashes[i] = int(hashlib.sha256(self.message.encode()).hexdigest(), 16) ^ self.mask
            else:
                hashes[i] = int(hashlib.sha256((str(self.public_keys[i]) + str(hashes[i-1])).encode()).hexdigest(), 16)
        return hashes[self.n-1], self.mask

def generate_rsa_public_key():
    # Generate an RSA key pair with a key size of 2048 bits
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    
    # Serialize the public key to PEM format
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Convert the PEM-formatted public key to a string
    public_key_string = public_pem.decode('utf-8')
    
    return public_key_string

def convert_public_key_string_to_binary(public_key_string):
    # Convert the public key string to bytes
    public_key_bytes = public_key_string.encode('utf-8')

    # Deserialize the public key from PEM format
    public_key = serialization.load_pem_public_key(public_key_bytes)

    # Serialize the public key to binary format
    public_key_binary = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.PKCS1
    )

    # Convert the binary-formatted public key to a string
    public_key_binary_string = public_key_binary.hex()

    return public_key_binary_string




def homeView(request):
    return render(request, "poll/home.html")

def registrationView(request):
    if request.method == "POST":
        form = RegistrationForm(request.POST)
        newUser = request.POST['username']
        if form.is_valid():
            cd = form.cleaned_data
            if cd['password'] == cd['confirm_password']:
                obj = form.save(commit=False)
                obj.set_password(obj.password)
                obj.save()
                # here the user should be created and a public key should be created and stored in the database.
                db = client['crypto']
                collection = db['users']
                new_user = collection.insert_one({'name' : newUser, 'public_key' : generate_rsa_public_key()})

                messages.success(request, 'You have been registered.')
                return redirect('home')
            else:
                return render(request, "poll/registration.html", {'form':form,'note':'password must match'})
    else:
        form = RegistrationForm()

    return render(request, "poll/registration.html", {'form':form})

def loginView(request):
    if request.method == "POST":
        usern = request.POST.get('username')
        passw = request.POST.get('password')
        user = authenticate(request, username=usern, password=passw)
        if user is not None:
            login(request,user)
            return redirect('dashboard')
        else:
            messages.success(request, 'Invalid username or password!')
            return render(request, "poll/login.html")
    else:
        return render(request, "poll/login.html")


@login_required
def logoutView(request):
    logout(request)
    return redirect('home')

@login_required
def dashboardView(request):
    return render(request, "poll/dashboard.html")

@login_required
def positionView(request):
    obj = Position.objects.all()
    return render(request, "poll/position.html", {'obj':obj})

@login_required
def candidateView(request, pos):
    obj = get_object_or_404(Position, pk = pos)


    if request.method == "POST":

        # x = select_random_user()
        # x.append(request.user)
        
        temp = ControlVote.objects.get_or_create(user=request.user, position=obj)[0]
        voter = temp.user.get_username()

        if temp.status == False:
            temp2 = Candidate.objects.get(pk=request.POST.get(obj.title))
            voted_to = temp2.name
            print(type(voted_to))

            temp2.total_vote += 1
            temp2.save()
            temp.status = True
            temp.save()

            db = client['crypto']
            collection = db['votes']
            user_collection = db['users']
            message = 'voted for the first time'

            public_keys = []
            obj1 = user_collection.find({'name' : voter})
            for x in obj1:
                public_keys.append(convert_public_key_string_to_binary(x['public_key']))
            
            x = select_random_user()
            print(x)
            for t in x:
                tem = user_collection.find({'name' : t.get_username()})
                for b in tem:
                    public_keys.append(convert_public_key_string_to_binary(b['public_key']))

            print(public_keys)


            ring_signature = RingSignature(message, public_keys, 0)
            signature, mask = ring_signature.sign()
            new_ring = str(signature)
            # print(new_ring)
            collection.insert_one({'ring': new_ring, 'vote_to': voted_to})

            return HttpResponseRedirect('/position/')
        else:
            # print(type(Candidate.objects.all()))
            # print(type(user_collection.find()))
            # print(temp)
            messages.success(request, 'you have already been voted this position.')
            return render(request, 'poll/candidate.html', {'obj':obj})
    else:
        return render(request, 'poll/candidate.html', {'obj':obj})

@login_required
def resultView(request):
    obj = Candidate.objects.all().order_by('position','-total_vote')
    return render(request, "poll/result.html", {'obj':obj})

@login_required
def votersView(request):
    db = client['crypto']
    collection = db['votes']
    temp = collection.find()
    obj = []
    for votes in temp:
        obj.append(votes)
    return render(request, "poll/votes.html", {'obj':obj})

@login_required
def candidateDetailView(request, id):
    obj = get_object_or_404(Candidate, pk=id)
    return render(request, "poll/candidate_detail.html", {'obj':obj})


@login_required
def changePasswordView(request):
    if request.method == "POST":
        form = PasswordChangeForm(user=request.user, data=request.POST)
        if form.is_valid():
            form.save()
            update_session_auth_hash(request,form.user)
            return redirect('dashboard')
    else:
        form = PasswordChangeForm(user=request.user)

    return render(request, "poll/password.html", {'form':form})


@login_required
def editProfileView(request):
    if request.method == "POST":
        form = ChangeForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            return redirect('dashboard')
    else:
        form = ChangeForm(instance=request.user)
    return render(request, "poll/edit_profile.html", {'form':form})
