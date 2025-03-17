```shell
echo "test,somethings else" > auth.csv
dotnet run auth.csv -l 0.0.0.0:8080 -t https://dns.google --https --pem-file crt.pem --key-file crt.key
curl http://127.0.0.1:8080/test/resolve?name=example.com
```
