import logging
from API.DBRequest import *
import azure.functions as func

import requests
import json
import bcrypt
import jwt


def main(req: func.HttpRequest) -> func.HttpResponse:
    payload = {
        "email": "a@a.com"
    }

    headers = {
        'Content-Type': 'application/json',
        'Access-Control-Request-Headers': '*',
        'api-key': 'hHLsFf7TGX3EfUVEOc1XOwbEfNUFaTq08dkXY6VGFAol2xKC0ijUq1mfrtKt2KWc',
    }

    response = requests.request(
        "POST", "https://eu-west-2.aws.data.mongodb-api.com/app/data-vghcq/endpoint/api/readUser", headers=headers, params=payload)

    if (response.text == "null"):
        raise HTTPException(status_code=401, detail="User not found")

    hashed_password = bcrypt.hashpw(userAPIModel.password.encode(
        'utf-8'), b'$2b$12$mCbAq1xSc21dn8o2Rj5Kou').decode("utf-8")

    json_response = json.loads(response.text)

    if (json_response["password"] != hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect password")

    # Create jwt
    jwt = CreateJWT({"id": json_response["_id"], "email": userAPIModel.email, "catalog": json_response["catalog"],
                    "exp": datetime.utcnow() + timedelta(days=1), "admin": json_response["admin"]})

    if (hashed_password == json.loads(response.text)['password']):
        raise HTTPException(
            status_code=response.status_code, detail={"jwt": jwt})
    else:
        raise HTTPException(status_code=401, detail={'result': 'unauthorized'})
