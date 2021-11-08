# dockerによるgolang開発環境(air含む)

## ビルドコマンド
~~~bash
docker-compose buid
~~~

## 依存関係解決コマンド
~~~bash
docker-compose run --rm app go mod tidy
~~~

## 起動コマンド
~~~bash
docker-compose up -d
~~~