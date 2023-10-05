# import logging

# import azure.functions as func
# from fastapi import FastAPI
# from fastapi.middleware.azure_functions import AzureFunctionsMiddleware
# from fastapi.routing import Request

# from FastAPI.main import app

# app.add_middleware(AzureFunctionsMiddleware)


# def main(req: func.HttpRequest) -> func.HttpResponse:
#     fastapi_req = Request(req.method, req.url.path,
#                           headers=req.headers, body=req.get_body())

#     fastapi_res = app(fastapi_req)

#     return func.HttpResponse(fastapi_res.body(), status_code=fastapi_res.status_code)

import logging
import azure.functions as func


# API
import pytest
import requests
import json
import uvicorn
from fastapi import FastAPI, HTTPException, Header, APIRouter, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# Data formatting
from pydantic import BaseModel
from typing import List

# .env
from dotenv import load_dotenv
import os

# Generic
import logging

# Hashing
import bcrypt

# JWT
import jwt
from datetime import datetime, timedelta

# Forgot Password
import os
import base64

# Paypal
import uuid

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins={"*"},
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# Load env variables

load_dotenv()

secret_key = os.environ["JWT_KEY"]
api_key = os.environ["API_KEY"]

headers = {
    'Content-Type': 'application/json',
    'Access-Control-Request-Headers': '*',
    'api-key': api_key,
}

responseHeaders = {
    "Access-Control-Allow-Origin": "https://ambitious-meadow-0c9567d03.3.azurestaticapps.net",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE",
    "Access-control-Allow-Headers": "Content-Type"
}

# Paypal
isPaypalLive = False

paypalSandboxUrl = "https://api-m.sandbox.paypal.com"
paypalSandboxClientID = "AVWAK5II6VGXna6DjVCs72XbwRNlQz2q2Lub2ibFSI82pczshtph3LDkHHak9GPXnC_S8_IftQ_ziZWQ"
paypalSandboxSecret = "ENrniU1XU4ouXhVJ84wwLkrOOgtr7CW2kdpUJANwWCMMoiZTJ7R-r2Mxsg11BCp25XotDoWiLp1qoa9m"

paypalLiveUrl = "https://api-m.paypal.com"
paypalLiveClientID = "AbNzg2jm2tPpeXVhiMRFcJRXi3Jk42SChRvA-DNXZWelre2dveiSx6p6LfMjh9jZ1Xqkwl8iyVINsBhs"
paypalLiveSecret = "EMBSZL_o8Ok8isVRo1OghZjDArDN80rinhCqAtBmofhxmvGQexgrb-V4_MB1aCM3oVO-d-Fk4qF2rpYA"


class TokenAPIModel(BaseModel):
    token: str


class EmailAPIModel(BaseModel):
    email: str


class UserAPIModel(BaseModel):
    email: str
    password: str


class IdModel(BaseModel):
    userId: str


class IdCatalogModel(BaseModel):
    catalogToAdd: str


class IdPasswordModel(BaseModel):
    password: str


class IncorrectQuestionModel(BaseModel):
    catalogItem: str
    questions: List[str]


class CatalogModel(BaseModel):
    catalogName: str


class JsonWebToken(BaseModel):
    admin: bool
    catalog: List[str]


class QuestionModel(BaseModel):
    question: str


class ExamAttemptModel(BaseModel):
    exam: str
    correctAnswers: List[str]  # List of Id's
    incorrectAnswers: List[str]
    skippedQuestions: List[str]
    timeCompleted: int  # In seconds


class PaypalOrderModel(BaseModel):
    intent: str
    value: str


class PaypalOrderModel(BaseModel):
    value: str


class PaypalOrderID(BaseModel):
    orderID: str


@app.get("/api")
async def get_data():
    return {"message": secret_key}


@app.post("/body")
async def test_body(userAPIModel: UserAPIModel):
    return {"email": userAPIModel.email, "password": userAPIModel.password}


def ErrorJson(e):
    print(e.with_traceback())
    raise HTTPException(status_code=500, detail=e.__str__())

# Generics


def IsTruthy(*vals):
    temp = True
    for val in vals:
        if (not bool(val)):
            temp = False
    return temp


def IsString(val):
    if type(val) == str:
        return True
    else:
        return False


def UserIdErrorResponse(data):
    data = json.loads(data)
    if "Error" in data and "message" in data["Error"]:
        error_message = data["Error"]["message"]
        # Occurs when id is in incorrect format
        if error_message == "ObjectId in must be a single string of 12 bytes or a string of 24 hex characters":
            raise HTTPException(status_code=400, detail=error_message)
        if error_message == "Cannot access member '_id' of undefined" or error_message == "Cannot access member 'catalog' of undefined":
            raise HTTPException(status_code=404, detail=error_message)


def UpdateErrorResponse(data):
    data = json.loads(data)
    if "modifiedCount" in data:
        if data["modifiedCount"] == 0:
            raise HTTPException(status_code=400, detail="No change was made")


def ErrorResponse(data):
    data = json.loads(data)
    if "Error" in data:
        if "Status code" in data:
            raise HTTPException(
                status_code=data["Status code"], detail=data["Error"])
        else:
            raise HTTPException(status_code=500, detail=data["Error"])


def DBRequest(method, url, payload):
    response = requests.request(method, url, headers=headers, params=payload)

    if (response.status_code == 200):
        UserIdErrorResponse(response.text)
        UpdateErrorResponse(response.text)
        ErrorResponse(response.text)

        raise HTTPException(status_code=response.status_code,
                            detail=json.loads(response.text))
    else:
        raise HTTPException(status_code=response.status_code,
                            detail=response.reason)


def IsAdmin(payload):
    try:
        if (bool(payload["admin"]) == False):
            return False
        else:
            return True
    except Exception:
        raise HTTPException(status_code=500, detail="Internal server error")


def HashPassword(password):
    return bcrypt.hashpw(password.encode('utf-8'), b'$2b$12$mCbAq1xSc21dn8o2Rj5Kou').decode("utf-8")

# JWT


def CreateJWT(payload):
    token = jwt.encode(payload, secret_key, algorithm="HS256")
    return token


def CheckJWTIsValid(Authorization):
    try:
        return jwt.decode(Authorization, secret_key, algorithms=['HS256'])

    except jwt.exceptions.DecodeError:
        raise HTTPException(status_code=401, detail="Invalid JWT")

    except jwt.exceptions.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="JWT expired")

# User


@app.post("/api/register")
async def Register(userAPIModel: UserAPIModel):
    # Make sure
    if not IsTruthy(userAPIModel.email, userAPIModel.password):
        raise HTTPException(
            status_code=400, detail="Invalid email or password")

    payload = {
        "email": userAPIModel.email,
        "password": HashPassword(userAPIModel.password),
        "admin": False
    }

    DBRequest("POST", "https://eu-west-2.aws.data.mongodb-api.com/app/data-vghcq/endpoint/api/createNewUser", payload)


@app.post("/login")
async def login(userAPIModel: UserAPIModel):
    """
    Function called to 'login' returns a jwt so the user can execute commands without logging in again
    :param userAPIModel: A model with a username and password
    :return: JWT with a payload including the users id, email, catalog, jwt exp and whether they're admin
    """
    if not IsTruthy(userAPIModel.email, userAPIModel.password):
        raise HTTPException(
            status_code=400, detail="Invalid email or password", headers=responseHeaders)

    payload = {
        "email": userAPIModel.email
    }

    response = requests.request(
        "POST", "https://eu-west-2.aws.data.mongodb-api.com/app/data-vghcq/endpoint/api/readUser", headers=headers, params=payload)

    if (response.text == "null"):
        raise HTTPException(
            status_code=401, detail="User not found", headers=responseHeaders)

    hashed_password = bcrypt.hashpw(userAPIModel.password.encode(
        'utf-8'), b'$2b$12$mCbAq1xSc21dn8o2Rj5Kou').decode("utf-8")

    json_response = json.loads(response.text)

    if (json_response["password"] != hashed_password):
        raise HTTPException(
            status_code=401, detail="Incorrect password", headers=responseHeaders)

    # Create jwt
    jwt = CreateJWT({"id": json_response["_id"], "email": userAPIModel.email, "catalog": json_response["catalog"],
                    "exp": datetime.utcnow() + timedelta(days=1), "admin": json_response["admin"]})

    if (hashed_password == json.loads(response.text)['password']):
        raise HTTPException(
            status_code=response.status_code, detail={"jwt": jwt}, headers=responseHeaders)
    else:
        raise HTTPException(status_code=401, detail={
                            'result': 'unauthorized'}, headers=responseHeaders)


@app.put("/updateUserCatalog")
async def UpdateUserCatalog(idCatalogModel: IdCatalogModel, Authorization: str = Header(..., convert_underscores=False)):
    # Validate
    if not IsTruthy(idCatalogModel.catalogToAdd):
        raise HTTPException(
            status_code=400, detail="Invalid userId or catalog item")

    jwt = CheckJWTIsValid(Authorization)

    # Check if they're an admin
    if (not IsAdmin(jwt)):
        raise HTTPException(status_code=401, detail="Unauthorized")

    payload = {
        "userId": jwt["id"],
        "catalogToAdd": idCatalogModel.catalogToAdd
    }

    DBRequest("PUT", "https://eu-west-2.aws.data.mongodb-api.com/app/data-vghcq/endpoint/api/updateUserCatalog", payload)


@app.post("/readUserCatalog")
async def ReadUserCatalog(Authorization: str = Header(..., convert_underscores=False)):
    """
    Pass through a jwt with the users id
    :param Authorization: encrypted jwt
    :return: An array of strings e.g ["JSA-41-01", "CPA-21-01"]
    """
    print(Authorization)
    jwt = CheckJWTIsValid(Authorization)

    payload = {
        "userId": jwt["id"]
    }

    DBRequest("POST", "https://eu-west-2.aws.data.mongodb-api.com/app/data-vghcq/endpoint/api/readUserCatalog", payload)

# Deprecated


@app.put("/forgotPassword")
async def ForgotPassword(idPasswordModel: IdPasswordModel, Authorization: str = Header(..., convert_underscores=False)):
    """
    Function for when the user forgets their password and needs to reset it
    :param idPasswordModel:  Model with a password
    :param Authorization: jwt
    :return: Returns response message
    """
    jwt = CheckJWTIsValid(Authorization)

    if not IsTruthy(idPasswordModel.password):
        raise HTTPException(status_code=400, detail="password")

    payload = {
        "userId": jwt["id"],
        "password": HashPassword(idPasswordModel.password)
    }

    DBRequest("PUT", "https://eu-west-2.aws.data.mongodb-api.com/app/data-vghcq/endpoint/api/updateUserPassword", payload)

# Questions


@app.post("/readAllCatalogQuestions")
async def ReadAllCatalogQuestions(catalogModel: CatalogModel, Authorization: str = Header(..., convert_underscores=False)):
    """
    Read all the questions from a given "catalog" e.g all the questions from the CPA-21-01
    :param catalogModel: Model with the name of the catalog
    :param Authorization: jwt
    :return: A response message
    """
    if not IsTruthy(catalogModel.catalogName,):
        raise HTTPException(status_code=400, detail="Invalid request body")

    jwt = CheckJWTIsValid(Authorization)

    if catalogModel.catalogName not in jwt["catalog"]:
        raise HTTPException(
            status_code=401, detail="You do not have this catalog item")

    payload = {
        "catalogName": catalogModel.catalogName
    }

    DBRequest("POST", "https://eu-west-2.aws.data.mongodb-api.com/app/data-vghcq/endpoint/api/readAllCatalogQuestions",
              payload)

# Incorrect Questions


@app.post("/createIncorrectQuestion")
async def CreateIncorrectQuestion(incorrectQuestionModel: IncorrectQuestionModel, Authorization: str = Header(..., convert_underscores=False)):
    """
    Creates an entry for an incorrect question, e.g a question a user has got wrong which
    can be easily retreived.
    :param incorrectQuestionModel: Model with the catalog name and the 'incorrect' questions
    :param Authorization: jwt
    :return: Response
    """
    if not IsTruthy(incorrectQuestionModel.catalogItem, incorrectQuestionModel.questions):
        raise HTTPException(status_code=400, detail="Invalid request body")

    jwt = CheckJWTIsValid(Authorization)

    payload = {
        "userId": jwt["id"],
        "catalogItem": incorrectQuestionModel.catalogItem,
        "questions": json.dumps(incorrectQuestionModel.questions)
    }

    DBRequest("POST", "https://eu-west-2.aws.data.mongodb-api.com/app/data-vghcq/endpoint/api/createIncorrectQuestions", payload)


@app.post("/readIncorrectQuestions")
async def ReadIncorrectQuestions(idCatalogModel: IdCatalogModel, Authorization: str = Header(..., convert_underscores=False)):
    """
    Read the incorrect questions a user has got wrong
    :param Authorization: jwt
    :param idCatalogModel: Get the incorrect questions for a specific catalog item
    :return: All the questions a user has got wrong
    """
    jwt = CheckJWTIsValid(Authorization)

    payload = {
        "userId": jwt["id"],
        "catalogItem": idCatalogModel.catalogToAdd
    }

    DBRequest("POST", "https://eu-west-2.aws.data.mongodb-api.com/app/data-vghcq/endpoint/api/readIncorrectQuestions", payload)

# Catalog


@app.post("/readAllCatalogs")
async def ReadAllCatalogs():
    """
    Reads all the catalogs available
    :return: An array of all the catalog objects e.g [{name: "JSA-41-01", ...}, {name: "CPA-21-01", ...}]
    """
    DBRequest(
        "POST", "https://eu-west-2.aws.data.mongodb-api.com/app/data-vghcq/endpoint/api/readAllCatalogs", {})


@app.post("/readCatalog")
async def ReadCatalog(catalogModel: CatalogModel):

    payload = {
        "catalogName": catalogModel.catalogName
    }

    DBRequest("POST", "https://eu-west-2.aws.data.mongodb-api.com/app/data-vghcq/endpoint/api/readCatalog", payload)


@app.post("/passwordResetRequest")
async def PasswordResetRequest(emailAPIModel: EmailAPIModel):

    # Generate a random token
    token_length = 32  # Adjust the length as needed
    random_bytes = os.urandom(token_length)
    token = base64.urlsafe_b64encode(random_bytes).rstrip(b'=').decode('utf-8')

    payload = {
        "email": emailAPIModel.email,
        "token": token
    }

    apiUri = 'https://api.elasticemail.com/v2'
    apiKey = "3121E72CC1797B4E75F7DD0023BA47919DEC723B405CD5C2EE769B4716D4E2224BD1EC2D064669AEE25533BD8114CB03"

    # apiKey = '00000000-0000-0000-0000-0000000000000'

    def sendEmail(method, url, data):
        data['apikey'] = apiKey
        if method == 'POST':
            result = requests.post(apiUri + url, data=data)
        elif method == 'PUT':
            result = requests.put(apiUri + url, data=data)
        elif method == 'GET':
            attach = ''
            for key in data:
                attach = attach + key + '=' + data[key] + '&'
            url = url + '?' + attach[:-1]
            result = requests.get(apiUri + url)

        jsonMy = result.json()

        if jsonMy['success'] is False:
            return jsonMy['error']

        return jsonMy['data']

    def Send(subject, EEfrom, fromName, to, url, isTransactional):
        return sendEmail('POST', '/email/send', {
            'subject': subject,
            'from': EEfrom,
            'fromName': fromName,
            "template": "Forgot Password",
            'to': to,
            "merge_url": url + "/" + token,
            'isTransactional': isTransactional})

    print(Send("Password Reset", "practicewithbyron@gmail.com", "PracticeWithByron", emailAPIModel.email + ";",
               emailAPIModel.url, False))

    DBRequest("POST", "https://eu-west-2.aws.data.mongodb-api.com/app/data-vghcq/endpoint/api/passwordResetRequest", payload)


@app.post("/getPasswordResetRequest")
async def GetPasswordResetRequest(tokenAPIModel: TokenAPIModel):

    payload = {
        "token": tokenAPIModel.token
    }

    DBRequest("POST", "https://eu-west-2.aws.data.mongodb-api.com/app/data-vghcq/endpoint/api/getPasswordResetRequest", payload)


@app.post("/changePassword")
async def ChangePassword(userAPIModel: UserAPIModel):

    payload = {
        "email": userAPIModel.email,
        "password": HashPassword(userAPIModel.password)
    }

    DBRequest("POST", "https://eu-west-2.aws.data.mongodb-api.com/app/data-vghcq/endpoint/api/changePassword", payload)

# Exam Attempts


@app.post("/createExamAttempt")
async def CreateExamAttempt(examAttemptModel: ExamAttemptModel, Authorization: str = Header(..., convert_underscores=False)):

    jwt = CheckJWTIsValid(Authorization)

    print(examAttemptModel.correctAnswers)

    payload = {
        "userId": jwt["id"],
        "exam": examAttemptModel.exam,
        "correctAnswers": examAttemptModel.correctAnswers,
        "incorrectAnswers": examAttemptModel.incorrectAnswers,
        "skippedQuestions": examAttemptModel.skippedQuestions,
        "timeCompleted": examAttemptModel.timeCompleted
    }

    json_payload = json.dumps(payload)

    print(json_payload)

    DBRequest("POST", "https://eu-west-2.aws.data.mongodb-api.com/app/data-vghcq/endpoint/api/createExamAttempt", json_payload)


# Paypal

def getAccessToken():
    baseUrl = paypalSandboxUrl
    clientID = paypalSandboxClientID
    clientSecret = paypalSandboxSecret
    if isPaypalLive == True:
        baseUrl = paypalLiveUrl
        clientID = paypalLiveClientID
        clientSecret = paypalLiveSecret
    payload = {
        "grant_type": "client_credentials"
    }
    return requests.post(f"{baseUrl}/v1/oauth2/token", data=payload, auth=(clientID, clientSecret)).json()["access_token"]


def createOrder(value):
    baseUrl = paypalSandboxUrl
    if isPaypalLive == True:
        baseUrl = paypalLiveUrl

    payload = {
        "intent": "CAPTURE",
        "purchase_units": [{
            "amount": {
                "currency_code": "GBP",
                "value": value
            }
        }]
    }
    accessToken = getAccessToken()
    json_payload = json.dumps(payload)

    response = requests.post(f"{baseUrl}/v2/checkout/orders", headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer " + accessToken,
        "PayPal-Request-Id": str(uuid.uuid4())
    }, data=json_payload)

    return json.loads(response.text)


@app.post("/orders")
async def PaypalOrders(paypalOrderModel: PaypalOrderModel):
    jsonResponse = createOrder(paypalOrderModel.value)
    return jsonResponse


def captureOrder(orderID):
    baseUrl = paypalSandboxUrl
    if isPaypalLive == True:
        baseUrl = paypalLiveUrl

    accessToken = getAccessToken()

    response = requests.post(f"{baseUrl}/v2/checkout/orders/{orderID}/capture", headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer " + accessToken
    })

    return json.loads(response.text)


@app.post("/orderscapture")
async def PaypalOrders(paypalOrderId: PaypalOrderID):
    return captureOrder(paypalOrderId.orderID)


async def main(req: func.HttpRequest, context: func.Context) -> func.HttpResponse:
    return await func.AsgiMiddleware(app).handle_async(req)
