from pathlib import Path
from django.db.backends.postgresql.psycopg_any import IsolationLevel #type: ignore
import os
from dotenv import load_dotenv
from typing import Any

load_dotenv()

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get("SECRET_KEY")

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []


# Application definition

INSTALLED_APPS = [
	'django.contrib.admin',
	'django.contrib.auth',
	'django.contrib.contenttypes',
	'django.contrib.sessions',
	'django.contrib.messages',
	'django.contrib.staticfiles',
  'corsheaders',
  'rest_framework',
  'django_backblaze_b2',
  'core',
]

MIDDLEWARE = [
  'corsheaders.middleware.CorsMiddleware',
	'django.middleware.security.SecurityMiddleware',
	'django.contrib.sessions.middleware.SessionMiddleware',
	'django.middleware.common.CommonMiddleware',
	'django.middleware.csrf.CsrfViewMiddleware',
	'django.contrib.auth.middleware.AuthenticationMiddleware',
	'django.contrib.messages.middleware.MessageMiddleware',
	'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'main.urls'

CORS_ALLOWED_ORIGINS: list[str] = [
  'http://localhost:8000',
]

CORS_ALLOW_CREDENTIALS = True

TEMPLATES: list[dict[str, Any]] = [
	{
		'BACKEND': 'django.template.backends.django.DjangoTemplates',
		'DIRS': [],
		'APP_DIRS': True,
		'OPTIONS': {
			'context_processors': [
				'django.template.context_processors.debug',
				'django.template.context_processors.request',
				'django.contrib.auth.context_processors.auth',
				'django.contrib.messages.context_processors.messages',
			],
		},
	},
]

WSGI_APPLICATION = 'main.wsgi.application'


# Database
# https://docs.djangoproject.com/en/4.2/ref/settings/#databases

DATABASES = {
  'default': {
	'ENGINE': 'django.db.backends.postgresql',
		'NAME': os.environ.get('DATABASE_NAME'),
		'USER': os.environ.get('DATABASE_USER'),
		'PASSWORD': os.environ.get('DATABASE_PASSWORD'),
		'HOST': os.environ.get('DATABASE_HOST'),
		'PORT': os.environ.get('DATABASE_PORT'),
  },
  'OPTIONS': {
		'isolation_level': IsolationLevel.SERIALIZABLE
	},
}


# Password validation
# https://docs.djangoproject.com/en/4.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
	{
		'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
	},
	{
		'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
	},
	{
		'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
	},
	{
		'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
	},
]


CACHES = {
  'default': {
	'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
	'LOCATION': 'unique-snowflake',
  },
  # add a cache via db table or memcached that can be accessed from multiple threads
  'django-backblaze-b2': {
	'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'
  }
}


BACKBLAZE_CONFIG = {
  'application_key_id': os.getenv('BACKBLAZE_KEY_ID'),
  'application_key': os.getenv('BACKBLAZE_KEY'),
  'bucket': os.getenv("BACKBLAZE_BUCKET")
}


DEFAULT_FILE_STORAGE ='django_backblaze_b2.storage.BackblazeB2Storage'


# Internationalization
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/

STATIC_URL = 'static/'

# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

AUTH_USER_MODEL = 'core.User'

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = os.environ.get("EMAIL_HOST")
EMAIL_HOST_USER = os.environ.get("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = os.environ.get("EMAIL_HOST_PASSWORD")
EMAIL_PORT = os.environ.get("EMAIL_PORT")
EMAIL_USE_TLS = os.environ.get("EMAIL_USE_TLS")