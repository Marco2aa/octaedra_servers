from fastapi import FastAPI, Path, Query, HTTPException, status, Depends
from typing import Optional
from pydantic import BaseModel,Field
import mysql.connector
from mysql.connector import Error
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
import jwt
from jwt.exceptions import InvalidTokenError, PyJWTError
from datetime import datetime, timedelta, timezone




app = FastAPI()

class Url(BaseModel):
    url: str

url_list = {

}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")



app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"], 
    allow_headers=["*"],  
)

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

def create_connection():
    try:
        connection = mysql.connector.connect(
            host='localhost',
            database='octaedra_servers',
            user='root',
            password=''
        )
        if connection.is_connected():
            print('Connexion à MySQL établie avec succès.')
            return connection
    except Error as e:
        print(f'Erreur lors de la connexion à MySQL : {e}')
        return None
    

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = "3a335659ed2f3c367f811ecb6d994224160ad2890c91e4869f8cf6776d1adf35"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES= 30

@app.get('/urls')
async def get_urls():
    connection = create_connection()
    if connection:
        cursor = connection.cursor()
        select_query = "SELECT * from url"
        cursor.execute(select_query)
        urls = cursor.fetchall()
        cursor.close()
        connection.close()
        urls_json = [{"id": row[0], "url": row[1]} for row in urls]
        return urls_json
    else:
        return {"Error" : "Erreur de recuperation des urls depuis la base de données ."}
    
@app.get('/get-url/{id_url}')
async def get_url_by_id(id_url: int):
    connection = create_connection()
    if connection:
        cursor = connection.cursor()
        select_query = f"SELECT * from url where id_url={id_url}"
        cursor.execute(select_query)
        url = cursor.fetchone()
        cursor.close()
        connection.close()
        if url:
            return {
                "id": url[0], 
                "url": url[1]
                }
        else:
            return {"Error": "L'URL avec l'ID spécifié n'existe pas."}
    else:
        return {"Error": "Erreur de récupération des données depuis la base de données."}
    
@app.post('/add-url')
def add_url(url: Url):
    connection = create_connection()
    if connection:
        try:
            cursor = connection.cursor()
            insert_query = "INSERT into url (url) values (%s)"
            cursor.execute(insert_query, (url.url,))
            connection.commit()
            cursor.close()
            connection.close()
            return {"Message":f"{url.url} correctement ajoutée à la base de données"}
        except Error as e:
            return HTTPException(status_code=500, detail=f"Erreur lors de l'ajout à la base de données : {e}")
    else:
        return HTTPException(status_code=500, detail="Erreur de connexion à la base de données.")
    

@app.put('/update-url/{id_url}')
def update_url(id_url: int, url: Url):
    connection = create_connection()
    if connection:
        try:
            cursor = connection.cursor()
            update_query = "UPDATE url SET url=%s WHERE id_url=%s"
            cursor.execute(update_query,(url.url, id_url))
            connection.commit()
            cursor.close()
            connection.close()
            return {"message": f"URL avec l'ID {id_url} mise à jour avec succès dans la base de données."}
        except Error as e:
            return HTTPException(status_code=500, detail=f"Erreur lors de la mise à jour de l'URL dans la base de données : {e}")
    else:
        return HTTPException(status_code=500, detail="Erreur de connexion à la base de données.")
    

    
@app.delete('delete-url/{id_url}')
def delete_url(id_url: int):
    connection = create_connection()
    if connection:
        try:
            cursor = connection.cursor()
            delete_query = "DELETE from url WHERE id_url = %s"
            cursor.execute(delete_query, (id_url,))
            connection.commit()
            cursor.close()
            connection.close()
            return {"message": f"URL avec l'ID {id_url} supprimée avec succès de la base de données."}
        except Error as e:
            return HTTPException(status_code=500, detail=f"Erreur lors de la suppression de l'URL dans la base de données : {e}")
    else:
        return HTTPException(status_code=500, detail="Erreur de connexion à la base de données.")
    

@app.get('/ports/{id_url}')
def get_ports_by_url(id_url: int):
    connection = create_connection()
    if connection:
        try:
            cursor = connection.cursor()
            select_query =  """ SELECT *
                                FROM port 
                                INNER JOIN serveurPort  ON port.id_port = serveurPort.id_port
                                WHERE serveurPort.id_url = %s"""
            cursor.execute(select_query,(id_url,))
            connection.commit()
            cursor.close()
            connection.close()
            return{"Message": "Ports correspondant au serveur recuperés avec succès de la base de données"}
        except Error as e :
            return HTTPException(status_scode = 500, detail="Erreur lors de la recupération des ports dans la base de données")
    else : 
        return HTTPException(status_code = 500, detail="Erreur de connexion à la base de données")
    

class User(BaseModel):
    username: str
    password: str
    disabled: Optional[bool] = False
    email: str

class UserInDB(User):
    hashed_password: str
    email: str = Field(..., alias="email") 

class UserSignup(BaseModel):
    username: str
    email: str
    password: str


class UserLogin(BaseModel):
    username: str
    password: str




def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_user_from_db(username: str):
    try:
        connection = create_connection()
        cursor = connection.cursor()
        select_query = "SELECT username, password, email FROM user WHERE username = %s"
        cursor.execute(select_query, (username,))
        user_data = cursor.fetchone()
        cursor.close()
        connection.close()
        if user_data:
            user_dict = {
                "username": user_data[0],
                "password": user_data[1],  
                "hashed_password": user_data[1],
                "email": user_data[2] 
            }
            return UserInDB(**user_dict)
        else:
            return None
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get user from database: {str(e)}")


def authenticate_user( username: str, password: str):
    user = get_user_from_db(username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user( form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except PyJWTError:
        raise credentials_exception
    user = get_user_from_db(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

@app.get("/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user


class UserOut(BaseModel):
    username: str

@app.post("/register", response_model=UserOut)
async def register(user: UserSignup):
    existing_user = get_user_from_db(user.username)
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    hashed_password = pwd_context.hash(user.password)
    
    try:
        connection = create_connection()
        cursor = connection.cursor()
        insert_query = "INSERT INTO user (username, password, disabled, email) VALUES (%s, %s, %s, %s)"
        cursor.execute(insert_query, (user.username, hashed_password, False, user.email))
        connection.commit()
        cursor.close()
        connection.close()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to register user: {str(e)}")
    
    return {"username":user.username}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)