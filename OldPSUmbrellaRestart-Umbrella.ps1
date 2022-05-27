Stop-Process -Id 7212 -Confirm -PassThru; get-service "*umbrella*" | restart-service
