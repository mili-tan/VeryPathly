```shell
echo "test,somethings else" > auth.csv
dotnet run auth.csv -l https:/0.0.0.0:8080 -t https://dns.google --use-path --https --pem-file crt.pem --key-file crt.key
curl http://127.0.0.1:8080/test/resolve?name=example.com
```
