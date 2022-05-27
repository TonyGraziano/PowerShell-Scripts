Stop-Process -Id 7 -Confirm -PassThru; Stop-Process -Id 9592 -Confirm -PassThru; get-service "*umbrella*" | restart-service
