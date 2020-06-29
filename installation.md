# CALISHOT Guidelines

## Indexing

```
python ../calishot/calishot.py import list.txt

python ../calishot/calishot.py check

sqlite-utils sites.db 'select url from sites where status="online" ' | jq -r '.[].url' > online.txt

python ../calishot/calistat.py index-site-list online.txt

python ../calishot/calistat.py build-index    

python ../calishot/calistat.py get-stats  


sqlite-utils index.db 'select uuid, title, authors, year, series, language, formats, publisher, tags, identifiers from summary where instr(formats, "mp3") >0  order by uuid limit 101'



```
## Deployment

1. Install poetry, datasette and it's plugins

```
poetry new calishot
poetry shell
poetry add datasette
poetry add datasette-json-html
poetry add datasette-pretty-json
```

You can eventually install it with virtualenv/pip if you don't want to use poetry: 

```
python -m venv calishot
. ./calishot/bin/activate
pip install datasette
pip install datasette-json-html
pip install datasette-pretty-json
````


2. Prepare the calishot settings:

Download the sqlite db file to the same directory and then


```
cat <<EOF > metadata.json 
{
    "databases": {
      "index": {
        "tables": {
            "summary": {
                "sort": "title",
                "searchmode": "raw"
            }
        }
      }
    }
  }
EOF
```

You can now run a local test:

```
datasette serve index.db --config sql_time_limit_ms:10000 --config allow_download:off --config max_returned_rows:2000  --config num_sql_threads:10 --metadata metadata.json
```

Open your browser to http://localhost:8001/ and check the result.

3. Now you're ready to publish :)

Install [heroku-cli](https://devcenter.heroku.com/articles/heroku-cli) then :


```
heroku login

datasette publish heroku index.db -n calishot-3 --install=datasette-json-html --install=datasette-pretty-json --extra-options="--config sql_time_limit_ms:10000 -
-config allow_download:off --config num_sql_threads:10 --config max_returned_rows:500" --metadata metadata.json
```
