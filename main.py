from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.requests import Request
import os
import json

app = FastAPI()
JSON_FILE = "known_exploited_vulnerabilities.json"

# attache static file
app.mount("/static", StaticFiles(directory="static"), name="static")

# html template
templates = Jinja2Templates(directory="template")


@app.get("/info", response_class=HTMLResponse)
def get_info(request: Request):
    """
    Return info about autor
    """
    context = {
        "request": request,
        "app_name": "FastAPI Application",
        "description": "This application allows you to get information about CVEs.",
        "author": "Mochurad Pavlo",
        "email": "mothuradpavlo@gmail.com",
    }

    return templates.TemplateResponse("info.html", context)


@app.get("/get/all/{page}", response_class=HTMLResponse)
def get_all(request: Request, page: int):
    """
    Return all cve
    """
    try:
        if not os.path.exists(JSON_FILE):
            raise FileNotFoundError(f"Where file?")

        with open(JSON_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)

        vulnerabilities = data["vulnerabilities"]

        start_index = (page - 1) * 40
        end_index = start_index + 40

        if start_index >= len(vulnerabilities) or page < 1:
            raise HTTPException(status_code=404, detail="Page not found")

        paginated_data = vulnerabilities[start_index:end_index]

        total_pages = (len(vulnerabilities) + 40 - 1) // 40

        return templates.TemplateResponse(
            "getall.html",
            {
                "request": request,
                "cves": paginated_data,
                "page": page,
                "total_pages": total_pages,
            },
        )

    except Exception as e:
        print(f"Error: {e}")
   

@app.get("/get/new", response_class=HTMLResponse)
def get_new(request: Request):
    try:
        if not os.path.exists(JSON_FILE):
            raise FileNotFoundError(f"Where file?")

        with open(JSON_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)

        vulnerabilities = data["vulnerabilities"]

        sorted_vulnerabilities = sorted(
            vulnerabilities,
            key=lambda x: x.get("dateAdded", ""),
            reverse=True
        )

        latest_vulnerabilities = sorted_vulnerabilities[:10]

        return templates.TemplateResponse(
            "getnew.html",
            {
                "request": request,
                "cves": latest_vulnerabilities,
            },
        )

    except Exception as e:
        print(f"Error: {e}")


@app.get("/get/known", response_class=HTMLResponse)
def get_known(request: Request):
    try:
        if not os.path.exists(JSON_FILE):
            raise FileNotFoundError(f"Where file?")

        with open(JSON_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)

        vulnerabilities = data["vulnerabilities"]

        known_vulnerabilities = [
            vuln for vuln in vulnerabilities
            if vuln["knownRansomwareCampaignUse"] == "Known"
        ]

        known_vulnerabilities = known_vulnerabilities[:10]

        return templates.TemplateResponse(
            "getknow.html",
            {
                "request": request,
                "cves": known_vulnerabilities,
            },
        )

    except Exception as e:
        print(f"Error: {e}")
    

@app.get("/get", response_class=HTMLResponse)
def search_cve(request: Request, query: str = Query(..., min_length=1)):
    try:
        if not os.path.exists(JSON_FILE):
            raise FileNotFoundError(f"Where file?")

        with open(JSON_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)

        vulnerabilities = data["vulnerabilities"]

        filtered_vulnerabilities = [
            vuln for vuln in vulnerabilities
            if query.lower() in json.dumps(vuln).lower()
        ]

        if not filtered_vulnerabilities:
            raise HTTPException(status_code=404, detail=f"CVE not found")

        return templates.TemplateResponse(
            "getsearch.html",
            {
                "request": request,
                "query": query,
                "cves": filtered_vulnerabilities,
            },
        )

    except Exception as e:
        print(f"Error: {e}")