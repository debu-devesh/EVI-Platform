@echo off
docker run -p 5000:5000 -v evi-persist:/persist --env-file .env evi-app
pause